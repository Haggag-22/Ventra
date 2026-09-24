"""Read GCP log rows from GCS archive objects.

Collectors keep their Cloud Logging filter semantics; the GCS archive backend resolves
where to read (bucket prefix) and applies the same filter to each row.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from collector.lib.limits import records_unlimited


class UnrecognizedFilterAtom(ValueError):
    """A filter clause matches no known grammar rule (e.g. a typo'd field name).

    Raised by both the Python matcher and the DuckDB translator so an unrecognized clause fails
    loud with an actionable message instead of silently matching every record.
    """

    def __init__(self, clause: str) -> None:
        self.clause = clause
        super().__init__(f"Unrecognized filter clause: {clause!r}. Check for typos in field names.")


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
        # Fail closed: a record whose timestamp is missing/unparseable cannot be confirmed to
        # fall inside the requested window, so it is EXCLUDED from windowed results (it used to
        # be included). Callers count these exclusions via entry_timestamp() so they surface as a
        # gap rather than vanishing silently. The DuckDB window predicate mirrors this.
        return False
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
    m = re.match(r"^logName:\((.+)\)$", text, re.DOTALL)
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

    m = re.match(r"^protoPayload\.methodName=\((.+)\)$", text)
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

    # Unrecognized clause — fail loud rather than silently matching every record. A typo in a
    # field name (e.g. resource.tpye="x") must not quietly widen results. The DuckDB translator
    # (gcp_log_filter_sql._atom_to_sql) raises the identical error for the same clause.
    raise UnrecognizedFilterAtom(text)


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


_BACKOFF_CAP_S = 60.0
_STALL_LIMIT_S_DEFAULT = 600.0
_DEFAULT_GCS_WORKERS = 20
# Raw rows filtered per DuckDB call in the GCS reader. Large enough to amortise DuckDB setup,
# small enough to cap the transient buffer well below a whole prefix.
_MATCH_BATCH = 50_000


def _export_parallel_workers() -> int:
    raw = os.environ.get("VENTRA_GCP_EXPORT_PARALLEL", "").strip()
    try:
        value = int(raw) if raw else 0
    except ValueError:
        value = 0
    return value if value > 0 else _DEFAULT_GCS_WORKERS


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
    return isinstance(exc, gcp_exc.Forbidden) and "ratelimitexceeded" in str(exc).lower()


class _PatientRetry:
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


def _project_log_prefixes(project_scope: list[str] | None) -> list[str]:
    return [f"projects/{p.strip()}/" for p in (project_scope or []) if p and p.strip()]


def entry_in_project_scope(entry: dict[str, Any], project_scope: list[str] | None) -> bool:
    prefixes = _project_log_prefixes(project_scope)
    if not prefixes:
        return True
    log_name = str(entry.get("logName") or entry.get("log_name") or "")
    if not log_name:
        return True
    return any(log_name.startswith(p) for p in prefixes)


def _emit_progress(on_progress: Callable[[str], None] | None, message: str) -> None:
    if on_progress is not None:
        on_progress(message)


def _record_stats(stats: dict[str, Any] | None, pattern: str, rows: int) -> None:
    if stats is None:
        return
    tables = stats.setdefault("prefixes_read", [])
    if pattern not in tables:
        tables.append(pattern)
    by_prefix = stats.setdefault("rows_by_prefix", {})
    by_prefix[pattern] = by_prefix.get(pattern, 0) + rows


_GCS_OBJECT_DATE = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")


def _gcs_object_in_window(name: str, start: datetime | None, end: datetime | None) -> bool:
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
    on_progress: Callable[[str], None] | None = None,
) -> Iterator[dict[str, Any]]:
    """Enumerate GCS log export objects and yield entries matching ``log_filter``.

    Prefix listing and object downloads both run in parallel (``VENTRA_GCP_EXPORT_PARALLEL``,
    default 20). Date-path pruning happens before any download is scheduled.
    """
    import concurrent.futures

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

    workers = _export_parallel_workers()
    emitted = 0

    def _list_one(prefix: str) -> tuple[str, list[str]]:
        _emit_progress(on_progress, f"[gcs] listing `{prefix}` …")
        try:
            names: list[str] = []
            for blob in client.list_blobs(bucket, prefix=prefix or None):
                name = blob.name or ""
                if not name.endswith(".json"):
                    continue
                if not _gcs_object_in_window(name, start, end):
                    continue
                names.append(name)
        except gcp_exc.Forbidden as exc:
            raise GcpExportAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpExportNotFound(str(exc)) from exc
        _emit_progress(on_progress, f"[gcs] `{prefix}` — {len(names):,} objects")
        return prefix, names

    list_workers = min(workers, max(len(prefixes), 1))
    prefix_blobs: list[tuple[str, list[str]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=list_workers) as pool:
        prefix_blobs = list(pool.map(_list_one, prefixes))

    def _download_one(blob_name: str) -> list[dict[str, Any]]:
        retry = _PatientRetry()
        while True:
            try:
                data = bucket.blob(blob_name).download_as_bytes()
                retry.progressed()
                return _parse_gcs_log_blob(data)
            except gcp_exc.GoogleAPIError as exc:
                if _is_quota_error(exc):
                    retry.backoff_or_raise(exc)
                    continue
                return []

    from collector.engine.gcp_log_filter_sql import GcpEntryMatcher

    matcher = GcpEntryMatcher(log_filter, start, end, project_scope, stats=stats)

    for prefix, blob_names in prefix_blobs:
        objects_seen = len(blob_names)
        prefix_emitted = 0
        if not blob_names:
            _record_stats(stats, prefix, 0)
            if objects_seen and not read_all_prefixes:
                return
            continue

        # Filter one prefix's rows through DuckDB in bounded batches (falling back to the Python
        # per-record loop on any error). Batching amortises DuckDB setup while capping the raw
        # rows held to _MATCH_BATCH — the download pool already materialises each blob, so this
        # does not raise peak memory beyond the existing behaviour.
        buffer: list[dict[str, Any]] = []

        def _flush(buf: list[dict[str, Any]], prefix: str = prefix):
            nonlocal emitted, prefix_emitted
            for entry in matcher.filter_batch(buf):
                yield entry
                emitted += 1
                prefix_emitted += 1
                if prefix_emitted % 10_000 == 0:
                    _emit_progress(
                        on_progress,
                        f"[gcs] `{prefix}` yielded {prefix_emitted:,} matching rows",
                    )
                if not records_unlimited(max_records) and emitted >= max_records:
                    return

        dl_workers = min(workers, len(blob_names))
        truncated = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=dl_workers) as pool:
            for entries in pool.map(_download_one, blob_names):
                buffer.extend(entries)
                if len(buffer) < _MATCH_BATCH:
                    continue
                yield from _flush(buffer)
                buffer = []
                if not records_unlimited(max_records) and emitted >= max_records:
                    truncated = True
                    break
        if not truncated and buffer:
            yield from _flush(buffer)

        _record_stats(stats, prefix, prefix_emitted)
        if not records_unlimited(max_records) and emitted >= max_records:
            return
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
            payload = None
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
    pass
