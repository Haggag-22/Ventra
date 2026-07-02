"""Read GCP log rows from BigQuery export tables or GCS archive objects.

Collectors keep their Cloud Logging filter semantics; export backends resolve *where*
to read (dataset table / bucket prefix) and apply the same filter to each row.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from collector.lib.limits import records_unlimited


@dataclass(frozen=True)
class BigQueryDatasetCheck:
    """Result of checking whether a configured log-export dataset exists."""

    ref: str
    project_id: str
    dataset_id: str
    found: bool
    table_count: int = 0
    message: str = ""


def check_bigquery_log_dataset(
    *,
    credentials: Any,
    dataset: str,
    default_project: str = "",
) -> BigQueryDatasetCheck:
    """Return whether ``dataset`` exists and how many tables it contains."""
    from google.api_core import exceptions as gcp_exc
    from google.cloud import bigquery

    bq_project, dataset_id = parse_bigquery_dataset(dataset, default_project=default_project)
    ref = f"{bq_project}.{dataset_id}"
    client = bigquery.Client(project=bq_project, credentials=credentials)
    try:
        tables = list(client.list_tables(f"{bq_project}.{dataset_id}"))
    except gcp_exc.NotFound:
        return BigQueryDatasetCheck(
            ref=ref,
            project_id=bq_project,
            dataset_id=dataset_id,
            found=False,
            message=f"Dataset '{ref}' was not found.",
        )
    except gcp_exc.Forbidden as exc:
        return BigQueryDatasetCheck(
            ref=ref,
            project_id=bq_project,
            dataset_id=dataset_id,
            found=False,
            message=f"Access denied listing dataset '{ref}': {exc}",
        )
    except gcp_exc.GoogleAPIError as exc:
        return BigQueryDatasetCheck(
            ref=ref,
            project_id=bq_project,
            dataset_id=dataset_id,
            found=False,
            message=str(exc),
        )

    count = len(tables)
    if count:
        suffix = "s" if count != 1 else ""
        message = f"Dataset '{ref}' found ({count} table{suffix})."
    else:
        message = f"Dataset '{ref}' found but contains no tables yet."
    return BigQueryDatasetCheck(
        ref=ref,
        project_id=bq_project,
        dataset_id=dataset_id,
        found=True,
        table_count=count,
        message=message,
    )


def parse_bigquery_dataset(raw: str, *, default_project: str = "") -> tuple[str, str]:
    """Return ``(project_id, dataset_id)`` from ``project.dataset`` or ``dataset``."""
    text = raw.strip().strip("`")
    if not text:
        raise ValueError("BigQuery dataset is required.")
    if "." in text:
        project, dataset = text.split(".", 1)
        return project.strip(), dataset.strip()
    if not default_project:
        raise ValueError(f"BigQuery dataset {raw!r} needs a project prefix (project.dataset).")
    return default_project.strip(), text


def normalize_gcs_bucket(raw: str) -> str:
    text = raw.strip()
    if text.startswith("gs://"):
        text = text[5:]
    return text.strip("/")


def normalize_log_entry(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a BigQuery row or GCS JSON object to Cloud Logging API shape."""
    out: dict[str, Any] = dict(raw)
    # BigQuery export uses the same field names; accept snake_case aliases.
    aliases = {
        "log_name": "logName",
        "insert_id": "insertId",
        "receive_timestamp": "receiveTimestamp",
        "text_payload": "textPayload",
        "json_payload": "jsonPayload",
        "proto_payload": "protoPayload",
    }
    for src, dst in aliases.items():
        if src in out and dst not in out:
            out[dst] = out.pop(src)
    ts = out.get("timestamp")
    if isinstance(ts, datetime):
        out["timestamp"] = ts.astimezone(UTC).isoformat().replace("+00:00", "Z")
    elif ts is not None and not isinstance(ts, str):
        out["timestamp"] = str(ts)
    resource = out.get("resource")
    if resource is not None and not isinstance(resource, dict):
        out["resource"] = {"type": str(resource), "labels": {}}
    return out


def entry_timestamp(entry: dict[str, Any]) -> datetime | None:
    raw = entry.get("timestamp")
    if isinstance(raw, datetime):
        return raw.astimezone(UTC)
    if not raw:
        return None
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(UTC)
    except ValueError:
        return None


def entry_in_window(entry: dict[str, Any], start: datetime | None, end: datetime | None) -> bool:
    if start is None and end is None:
        return True
    ts = entry_timestamp(entry)
    if ts is None:
        return True
    if start is not None and ts < start:
        return False
    return end is None or ts <= end


def matches_gcp_log_filter(entry: dict[str, Any], filter_str: str) -> bool:
    """Evaluate a Cloud Logging filter against a log entry dict (export backends)."""
    expr = filter_str.strip()
    if not expr:
        return True
    return _eval_or(entry, _strip_outer_parens(expr))


def _strip_outer_parens(expr: str) -> str:
    text = expr.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        wrapped = True
        for i, ch in enumerate(text):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(text) - 1:
                    wrapped = False
                    break
        if wrapped:
            text = text[1:-1].strip()
        else:
            break
    return text


def _split_top_level(text: str, op: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    i = 0
    op_upper = op.upper()
    op_len = len(op)
    while i < len(text):
        if text[i] == "(":
            depth += 1
            buf.append(text[i])
            i += 1
            continue
        if text[i] == ")":
            depth -= 1
            buf.append(text[i])
            i += 1
            continue
        if depth == 0 and text[i : i + op_len].upper() == op_upper:
            parts.append("".join(buf).strip())
            buf = []
            i += op_len
            continue
        buf.append(text[i])
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _eval_or(entry: dict[str, Any], expr: str) -> bool:
    parts = _split_top_level(expr, " OR ")
    if len(parts) > 1:
        return any(_eval_and(entry, p) for p in parts)
    return _eval_and(entry, expr)


def _eval_and(entry: dict[str, Any], expr: str) -> bool:
    parts = _split_top_level(expr, " AND ")
    if len(parts) > 1:
        return all(_eval_not(entry, p) for p in parts)
    return _eval_not(entry, expr)


def _eval_not(entry: dict[str, Any], expr: str) -> bool:
    text = expr.strip()
    if text.upper().startswith("NOT "):
        return not _eval_or(entry, text[4:].strip())
    return _eval_atom(entry, text)


def _eval_atom(entry: dict[str, Any], expr: str) -> bool:
    text = _strip_outer_parens(expr.strip())
    if not text:
        return True

    # logName:("a" OR "b") or logName:"fragment"
    m = re.match(r'^logName:\((.+)\)$', text, re.DOTALL)
    if m:
        inner = m.group(1)
        options = re.findall(r'"([^"]+)"', inner)
        return any(_log_name_matches(entry, opt) for opt in options)
    m = re.match(r'^logName:"([^"]+)"$', text)
    if m:
        return _log_name_matches(entry, m.group(1))

    m = re.match(r'^resource\.type="([^"]+)"$', text)
    if m:
        return _resource_type(entry) == m.group(1)

    m = re.match(r'^protoPayload\.serviceName="([^"]+)"$', text)
    if m:
        return _nested(entry, "protoPayload", "serviceName") == m.group(1)

    m = re.match(r'^protoPayload\.methodName=\((.+)\)$', text)
    if m:
        options = re.findall(r'"([^"]+)"', m.group(1))
        method = _nested(entry, "protoPayload", "methodName")
        return method in options

    m = re.match(r'^protoPayload\.methodName="([^"]+)"$', text)
    if m:
        return _nested(entry, "protoPayload", "methodName") == m.group(1)

    m = re.match(r"^severity>=(\w+)$", text)
    if m:
        return _severity_rank(str(entry.get("severity") or "")) >= _severity_rank(m.group(1))

    m = re.match(r"^jsonPayload\.(\w+)=\*$", text)
    if m:
        payload = entry.get("jsonPayload") or {}
        return isinstance(payload, dict) and m.group(1) in payload and payload[m.group(1)] is not None

    m = re.match(r"^jsonPayload\.(\w+)=(true|false)$", text, re.IGNORECASE)
    if m:
        payload = entry.get("jsonPayload") or {}
        if not isinstance(payload, dict):
            return False
        val = payload.get(m.group(1))
        want = m.group(2).lower() == "true"
        return bool(val) == want

    m = re.match(r"^httpRequest\.(\w+)=(true|false)$", text, re.IGNORECASE)
    if m:
        payload = entry.get("httpRequest") or {}
        if not isinstance(payload, dict):
            return False
        val = payload.get(m.group(1))
        want = m.group(2).lower() == "true"
        return bool(val) == want

    m = re.match(r'^resource\.labels\.(\w+)="([^"]+)"$', text)
    if m:
        resource = entry.get("resource") or {}
        labels = resource.get("labels") if isinstance(resource, dict) else {}
        if not isinstance(labels, dict):
            labels = {}
        return str(labels.get(m.group(1)) or "") == m.group(2)

    # Log Explorer "has" operator on a resource label (e.g. zone:"us-central1" matches
    # us-central1-a) — used by the global regions scope.
    m = re.match(r'^resource\.labels\.(\w+):"([^"]+)"$', text)
    if m:
        resource = entry.get("resource") or {}
        labels = resource.get("labels") if isinstance(resource, dict) else {}
        if not isinstance(labels, dict):
            labels = {}
        return m.group(2) in str(labels.get(m.group(1)) or "")

    m = re.match(r"^jsonPayload\.([\w.]+):\*$", text)
    if m:
        return _nested_present(entry, "jsonPayload", *m.group(1).split("."))

    # Unknown clause — do not drop rows on partial grammar support.
    return True


def _log_name_matches(entry: dict[str, Any], fragment: str) -> bool:
    log_name = str(entry.get("logName") or entry.get("log_name") or "")
    decoded = unquote(fragment)
    return fragment in log_name or decoded in log_name


def _resource_type(entry: dict[str, Any]) -> str:
    resource = entry.get("resource") or {}
    if isinstance(resource, dict):
        return str(resource.get("type") or "")
    return str(resource)


def _nested(entry: dict[str, Any], *path: str) -> str:
    cur: Any = entry
    for key in path:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key)
    return str(cur or "")


def _nested_present(entry: dict[str, Any], *path: str) -> bool:
    cur: Any = entry
    for key in path:
        if not isinstance(cur, dict):
            return False
        cur = cur.get(key)
        if cur is None:
            return False
    return True


_SEVERITY_RANK = {
    "DEFAULT": 0,
    "DEBUG": 100,
    "INFO": 200,
    "NOTICE": 300,
    "WARNING": 400,
    "ERROR": 500,
    "CRITICAL": 600,
    "ALERT": 700,
    "EMERGENCY": 800,
}


def _severity_rank(name: str) -> int:
    return _SEVERITY_RANK.get(name.upper(), 0)


def bigquery_table_patterns(table_id: str) -> list[tuple[str, bool]]:
    """Return ``(table_pattern, uses_wildcard)`` pairs for a configured table id.

    Log Router BigQuery sinks shard rows into daily tables such as
    ``cloudaudit_googleapis_com_activity_20250628``, not a single static table name.
    """
    if table_id == "_Default":
        return [(table_id, False)]
    base = table_id.rstrip("_")
    patterns: list[tuple[str, bool]] = [(table_id, False)]
    wildcard = f"{base}_*"
    if wildcard != table_id:
        patterns.append((wildcard, True))
    return patterns


_BQ_PAGE_SIZE = 10_000
_BACKOFF_CAP_S = 60.0  # read quotas are per-minute; they fully refill within 60s
_STALL_LIMIT_S_DEFAULT = 600.0


def _export_stall_limit_s() -> float:
    raw = os.environ.get("VENTRA_GCP_LOG_STALL_LIMIT_S", "").strip()
    try:
        value = float(raw) if raw else 0.0
    except ValueError:
        value = 0.0
    return value if value > 0 else _STALL_LIMIT_S_DEFAULT


def _is_quota_error(exc: Exception) -> bool:
    from google.api_core import exceptions as gcp_exc

    if isinstance(exc, gcp_exc.ResourceExhausted):
        return True
    # BigQuery surfaces some rate quotas as 403 rateLimitExceeded, not 429.
    return isinstance(exc, gcp_exc.Forbidden) and "ratelimitexceeded" in str(exc).lower()


class _PatientRetry:
    """Quota backoff that delays, never caps: a 429 mid-range means wait and re-issue.

    Patience resets whenever the scan makes progress; collection is only abandoned after
    the stall limit of zero-progress quota errors, at which point the block is no longer a
    refilling per-minute quota.
    """

    def __init__(self) -> None:
        self._attempt = 0
        self._stalled = 0.0

    def progressed(self) -> None:
        self._attempt = 0
        self._stalled = 0.0

    def backoff_or_raise(self, exc: Exception) -> None:
        if self._stalled >= _export_stall_limit_s():
            raise GcpExportRateLimited(
                f"export read quota stayed exhausted ~{self._stalled:.0f}s without progress: {exc}"
            ) from exc
        self._attempt += 1
        delay = min(2.0**self._attempt, _BACKOFF_CAP_S) + random.uniform(0.0, 1.0)
        time.sleep(delay)
        self._stalled += delay


def _bq_page_limit(max_records: int, emitted: int) -> int:
    if records_unlimited(max_records):
        return _BQ_PAGE_SIZE
    remaining = max_records - emitted
    if remaining <= 0:
        return 0
    return min(_BQ_PAGE_SIZE, remaining)


def _bq_timestamp_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _project_log_prefixes(project_scope: list[str] | None) -> list[str]:
    return [f"projects/{p.strip()}/" for p in (project_scope or []) if p and p.strip()]


def entry_in_project_scope(entry: dict[str, Any], project_scope: list[str] | None) -> bool:
    """True when the entry's logName belongs to one of the selected projects.

    Entries without a logName are kept — scoping must never silently drop evidence the
    filter grammar cannot attribute.
    """
    prefixes = _project_log_prefixes(project_scope)
    if not prefixes:
        return True
    log_name = str(entry.get("logName") or entry.get("log_name") or "")
    if not log_name:
        return True
    return any(log_name.startswith(p) for p in prefixes)


def _bq_query_page(
    client: Any,
    *,
    bq_project: str,
    dataset_id: str,
    pattern: str,
    uses_wildcard: bool,
    start: datetime | None,
    end: datetime | None,
    cursor_ts: datetime | None,
    cursor_insert_id: str,
    project_scope: list[str] | None,
    page_limit: int,
) -> Any:
    """Run one keyset-paginated BigQuery page.

    Rows are totally ordered by ``(timestamp DESC, insertId DESC)`` so the
    ``(cursor_ts, cursor_insert_id)`` keyset resumes exactly after the last row of the
    previous page — rows sharing a boundary timestamp are neither dropped nor re-read.
    Date-shard pruning (``_TABLE_SUFFIX``) stays on every page; the shard range never
    changes while paginating.
    """
    from google.cloud import bigquery

    table_ref = f"`{bq_project}.{dataset_id}.{pattern}`"
    where_parts: list[str] = []
    params: list[Any] = []

    if start is not None:
        where_parts.append("timestamp >= TIMESTAMP(@ts_start)")
        params.append(bigquery.ScalarQueryParameter("ts_start", "STRING", _bq_timestamp_iso(start)))
    if end is not None:
        where_parts.append("timestamp <= TIMESTAMP(@ts_end)")
        params.append(bigquery.ScalarQueryParameter("ts_end", "STRING", _bq_timestamp_iso(end)))
    if cursor_ts is not None:
        where_parts.append(
            "(timestamp < TIMESTAMP(@cursor_ts) OR "
            "(timestamp = TIMESTAMP(@cursor_ts) AND IFNULL(insertId, '') < @cursor_id))"
        )
        params.extend(
            [
                bigquery.ScalarQueryParameter("cursor_ts", "STRING", _bq_timestamp_iso(cursor_ts)),
                bigquery.ScalarQueryParameter("cursor_id", "STRING", cursor_insert_id),
            ]
        )
    if uses_wildcard and start is not None and end is not None:
        where_parts.append("_TABLE_SUFFIX BETWEEN @suffix_start AND @suffix_end")
        params.extend(
            [
                bigquery.ScalarQueryParameter(
                    "suffix_start", "STRING", start.astimezone(UTC).strftime("%Y%m%d")
                ),
                bigquery.ScalarQueryParameter(
                    "suffix_end", "STRING", end.astimezone(UTC).strftime("%Y%m%d")
                ),
            ]
        )
    scope_prefixes = _project_log_prefixes(project_scope)
    if scope_prefixes:
        clauses = []
        for i, scope_prefix in enumerate(scope_prefixes):
            clauses.append(f"STARTS_WITH(logName, @project_scope_{i})")
            params.append(
                bigquery.ScalarQueryParameter(f"project_scope_{i}", "STRING", scope_prefix)
            )
        where_parts.append(f"({' OR '.join(clauses)})")

    where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
    sql = (
        f"SELECT * FROM {table_ref} "
        f"{where_sql} "
        f"ORDER BY timestamp DESC, IFNULL(insertId, '') DESC "
        f"LIMIT @page_limit"
    )
    params.append(bigquery.ScalarQueryParameter("page_limit", "INT64", page_limit))
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    return client.query(sql, job_config=job_config).result()


def iter_bigquery_log_entries(
    *,
    credentials: Any,
    project_id: str,
    dataset: str,
    tables: list[str],
    log_filter: str,
    start: datetime | None,
    end: datetime | None,
    max_records: int,
    read_all_tables: bool = False,
    project_scope: list[str] | None = None,
    stats: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Query exported log tables and yield entries matching ``log_filter``.

    Paginates through the full result set — a cap applies only when the analyst set
    ``max_records``. When ``start`` and ``end`` are both ``None``, every row in the
    matching export tables is eligible. ``read_all_tables`` unions every listed table
    (vpc_flows ×2, per-stream agent/engine logs); otherwise the listed tables are
    alternative names for one log and reading stops at the first that yields rows.
    ``stats`` (optional) collects the tables read and per-table row counts for the
    collection summary.
    """
    from google.api_core import exceptions as gcp_exc
    from google.cloud import bigquery

    bq_project, dataset_id = parse_bigquery_dataset(dataset, default_project=project_id)
    client = bigquery.Client(project=bq_project, credentials=credentials)
    emitted = 0
    last_error: Exception | None = None

    for table_id in tables:
        if not records_unlimited(max_records) and emitted >= max_records:
            return
        table_emitted = 0
        for pattern, uses_wildcard in bigquery_table_patterns(table_id):
            pattern_emitted = 0
            cursor_ts: datetime | None = None
            cursor_insert_id = ""
            table_missing = False
            retry = _PatientRetry()
            while True:
                page_limit = _bq_page_limit(max_records, emitted)
                if page_limit <= 0:
                    return
                try:
                    rows = list(
                        _bq_query_page(
                            client,
                            bq_project=bq_project,
                            dataset_id=dataset_id,
                            pattern=pattern,
                            uses_wildcard=uses_wildcard,
                            start=start,
                            end=end,
                            cursor_ts=cursor_ts,
                            cursor_insert_id=cursor_insert_id,
                            project_scope=project_scope,
                            page_limit=page_limit,
                        )
                    )
                except gcp_exc.NotFound:
                    table_missing = True
                    break
                except gcp_exc.GoogleAPIError as exc:
                    if _is_quota_error(exc):
                        retry.backoff_or_raise(exc)
                        continue  # re-issue the same page; backoff delays, it never caps
                    if isinstance(exc, gcp_exc.Forbidden):
                        raise GcpExportAccessDenied(str(exc)) from exc
                    last_error = exc
                    break
                retry.progressed()

                if not rows:
                    break

                for row in rows:
                    entry = normalize_log_entry(dict(row))
                    if not entry_in_window(entry, start, end):
                        continue
                    if not entry_in_project_scope(entry, project_scope):
                        continue
                    if not matches_gcp_log_filter(entry, log_filter):
                        continue
                    yield entry
                    emitted += 1
                    pattern_emitted += 1
                    if not records_unlimited(max_records) and emitted >= max_records:
                        _record_stats(stats, pattern, pattern_emitted)
                        return

                if len(rows) < page_limit:
                    break
                last = normalize_log_entry(dict(rows[-1]))
                cursor_ts = entry_timestamp(last)
                if cursor_ts is None:
                    break
                cursor_insert_id = str(last.get("insertId") or "")

            table_emitted += pattern_emitted
            if not table_missing:
                _record_stats(stats, pattern, pattern_emitted)
            if pattern_emitted:
                break  # this table name form held the data; skip its alternate form
        if table_emitted and not read_all_tables:
            return

    if last_error is not None:
        raise GcpExportError(str(last_error))
    return


def _record_stats(stats: dict[str, Any] | None, pattern: str, rows: int) -> None:
    if stats is None:
        return
    tables = stats.setdefault("tables_read", [])
    if pattern not in tables:
        tables.append(pattern)
    by_table = stats.setdefault("rows_by_table", {})
    by_table[pattern] = by_table.get(pattern, 0) + rows


_GCS_OBJECT_DATE = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")


def _gcs_object_in_window(name: str, start: datetime | None, end: datetime | None) -> bool:
    """Prefix-level window pruning: skip objects whose /YYYY/MM/DD/ path is out of range.

    Objects without a recognizable date path are kept and filtered per entry instead.
    """
    if start is None and end is None:
        return True
    match = _GCS_OBJECT_DATE.search(name)
    if not match:
        return True
    try:
        day = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=UTC)
    except ValueError:
        return True
    if start is not None and day.date() < start.astimezone(UTC).date():
        return False
    return end is None or day.date() <= end.astimezone(UTC).date()


def iter_gcs_log_entries(
    *,
    credentials: Any,
    bucket_name: str,
    prefixes: list[str],
    log_filter: str,
    start: datetime | None,
    end: datetime | None,
    max_records: int,
    read_all_prefixes: bool = False,
    project_scope: list[str] | None = None,
    stats: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Enumerate GCS log export objects and yield entries matching ``log_filter``.

    Every object under each prefix is read (the listing iterator paginates fully); only an
    analyst-set ``max_records`` stops early. Objects with an out-of-window ``/YYYY/MM/DD/``
    path are pruned by name without being downloaded. Same first-match vs union semantics
    over ``prefixes`` as the BigQuery table candidates.
    """
    from google.api_core import exceptions as gcp_exc
    from google.cloud import storage

    bucket_name = normalize_gcs_bucket(bucket_name)
    client = storage.Client(credentials=credentials)
    try:
        bucket = client.bucket(bucket_name)
    except gcp_exc.Forbidden as exc:
        raise GcpExportAccessDenied(str(exc)) from exc
    except gcp_exc.NotFound as exc:
        raise GcpExportNotFound(str(exc)) from exc

    emitted = 0
    for prefix in prefixes:
        objects_seen = 0
        prefix_emitted = 0
        retry = _PatientRetry()
        try:
            blobs = client.list_blobs(bucket, prefix=prefix or None)
            for blob in blobs:
                name = blob.name or ""
                if not name.endswith(".json"):
                    continue
                objects_seen += 1
                if not _gcs_object_in_window(name, start, end):
                    continue
                while True:
                    try:
                        data = blob.download_as_bytes()
                        retry.progressed()
                        break
                    except gcp_exc.GoogleAPIError as exc:
                        if _is_quota_error(exc):
                            retry.backoff_or_raise(exc)
                            continue
                        data = b""
                        break
                for entry in _parse_gcs_log_blob(data):
                    entry = normalize_log_entry(entry)
                    if not entry_in_window(entry, start, end):
                        continue
                    if not entry_in_project_scope(entry, project_scope):
                        continue
                    if not matches_gcp_log_filter(entry, log_filter):
                        continue
                    yield entry
                    emitted += 1
                    prefix_emitted += 1
                    if not records_unlimited(max_records) and emitted >= max_records:
                        _record_stats(stats, prefix, prefix_emitted)
                        return
        except gcp_exc.Forbidden as exc:
            raise GcpExportAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpExportNotFound(str(exc)) from exc
        _record_stats(stats, prefix, prefix_emitted)
        if objects_seen and not read_all_prefixes:
            return


def _parse_gcs_log_blob(data: bytes) -> list[dict[str, Any]]:
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None  # multi-entry JSONL also starts with "{" — parse per line below
        if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
            return [e for e in payload["entries"] if isinstance(e, dict)]
        if isinstance(payload, dict):
            return [payload]
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


class GcpExportError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class GcpExportAccessDenied(GcpExportError):
    pass


class GcpExportNotFound(GcpExportError):
    pass


class GcpExportRateLimited(GcpExportError):
    """Export read quota (429 / rateLimitExceeded) stayed exhausted past the stall limit."""
