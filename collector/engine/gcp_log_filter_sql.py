"""DuckDB-backed evaluation of Cloud Logging filters (fast path for ``matches_gcp_log_filter``).

The Python reference implementation lives in :mod:`collector.engine.gcp_log_export`
(``matches_gcp_log_filter`` and the ``entry_in_window`` / ``entry_in_project_scope`` helpers).
That per-record loop is regex-heavy and runs once per row; for large GCS-export pulls the
filtering dominates. This module translates the *same* grammar — atom for atom, using the
*same* boolean-splitting helpers — into a single SQL ``WHERE`` expression that DuckDB evaluates
over a JSON column in vectorised C++.

Design guarantees (why this is safe to swap in):

* **Identical boolean structure.** ``filter_to_sql`` mirrors ``_eval_or`` → ``_eval_and`` →
  ``_eval_not`` → ``_eval_atom`` exactly, reusing ``_split_top_level`` / ``_strip_outer_parens``
  from the reference module. An atom neither grammar recognises raises
  :class:`~collector.engine.gcp_log_export.UnrecognizedFilterAtom` on both paths (a typo must
  fail loud, not silently match every record).
* **Field aliasing parity.** The reference filters *normalised* entries (``normalize_log_entry``
  maps ``log_name`` → ``logName`` etc.). We filter the *raw* entry and reproduce that aliasing
  by ``COALESCE``-ing camelCase and snake_case JSON paths.
* **Fail closed to Python.** Any atom we are not 100% confident we can translate faithfully
  (currently the ``=true``/``=false`` truthiness forms) raises :class:`FilterTranslationError`,
  and callers fall back to the reference Python path. Combined with the
  ``VENTRA_GCP_DUCKDB_FILTER`` master switch and a blanket try/except around execution, a bug
  in this path can never silently drop or corrupt evidence — it degrades to the old loop.

Output is always the *original* raw entry (DuckDB only decides which rows pass); callers run the
untouched ``normalize_log_entry`` on survivors, so downstream shape is byte-identical.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from collector.engine.gcp_log_export import (
    _SEVERITY_RANK,
    UnrecognizedFilterAtom,
    _severity_rank,
    _split_top_level,
    _strip_outer_parens,
)

_ENABLE_ENV = "VENTRA_GCP_DUCKDB_FILTER"
_DISABLED_VALUES = frozenset({"0", "false", "no", "off"})

# Top-level keys that ``normalize_log_entry`` rewrites from snake_case to camelCase. We accept
# either spelling in SQL so a raw entry filters the same way the normalised one would.
_ALIAS: dict[str, str] = {
    "logName": "log_name",
    "protoPayload": "proto_payload",
    "jsonPayload": "json_payload",
    "textPayload": "text_payload",
}


class FilterTranslationError(Exception):
    """A filter atom is recognised by the Python grammar but is not faithfully translatable.

    Raising this (rather than guessing) forces the caller onto the reference Python path for the
    whole read, preserving exact semantics.
    """


def duckdb_filtering_enabled() -> bool:
    """True unless ``VENTRA_GCP_DUCKDB_FILTER`` is set to a falsey value."""
    return os.environ.get(_ENABLE_ENV, "").strip().lower() not in _DISABLED_VALUES


def duckdb_available() -> bool:
    try:
        import duckdb  # noqa: F401
    except Exception:  # noqa: BLE001 — any import failure means: use Python path
        return False
    return True


# --- SQL literal / path helpers -----------------------------------------------------------


def _sql_str(value: str) -> str:
    """A safely-quoted SQL string literal (doubles embedded single quotes)."""
    return "'" + value.replace("'", "''") + "'"


def _path_variants(path: str) -> list[str]:
    """camelCase path plus its snake_case alias (first segment only), mirroring normalize."""
    head, sep, rest = path.partition(".")
    out = [path]
    alt = _ALIAS.get(head)
    if alt is not None:
        out.append(alt + (sep + rest if sep else ""))
    return out


def _json_path(base: str, path: str) -> str:
    """A JSON path expression for ``$.<base><path>`` (base is ``""`` or ``"e."``)."""
    return f"$.{base}{path}"


def _str_coalesced(col: str, base: str, path: str) -> str:
    """``COALESCE(json_extract_string(...camel...), ...snake..., '')`` → never NULL."""
    parts = [f"json_extract_string({col}, {_sql_str(_json_path(base, p))})" for p in _path_variants(path)]
    parts.append("''")
    return f"COALESCE({', '.join(parts)})"


def _present_not_null(col: str, base: str, path: str) -> str:
    """True when the value at ``path`` (or its alias) exists and is not JSON ``null``.

    Mirrors the Python ``x is not None`` / ``_nested_present`` presence checks.
    """
    clauses = []
    for p in _path_variants(path):
        ex = f"json_extract({col}, {_sql_str(_json_path(base, p))})"
        clauses.append(f"({ex} IS NOT NULL AND {ex}::VARCHAR <> 'null')")
    return "(" + " OR ".join(clauses) + ")"


def _severity_case(col: str, base: str) -> str:
    sev = _str_coalesced(col, base, "severity")
    whens = " ".join(f"WHEN {_sql_str(name)} THEN {rank}" for name, rank in _SEVERITY_RANK.items())
    return f"(CASE UPPER({sev}) {whens} ELSE 0 END)"


# --- grammar translation (mirrors gcp_log_export._eval_*) ----------------------------------


def filter_to_sql(filter_str: str, col: str, base: str) -> str:
    """Translate a Cloud Logging filter into a SQL boolean over JSON column ``col``.

    ``base`` is the JSON-path prefix to the entry object: ``""`` when each row *is* the entry,
    or ``"e."`` when the entry is wrapped as ``{"i": <idx>, "e": <entry>}``.
    """
    expr = (filter_str or "").strip()
    if not expr:
        return "TRUE"
    return _or_to_sql(_strip_outer_parens(expr), col, base)


def _or_to_sql(expr: str, col: str, base: str) -> str:
    parts = _split_top_level(expr, " OR ")
    if len(parts) > 1:
        return "(" + " OR ".join(_and_to_sql(p, col, base) for p in parts) + ")"
    return _and_to_sql(expr, col, base)


def _and_to_sql(expr: str, col: str, base: str) -> str:
    parts = _split_top_level(expr, " AND ")
    if len(parts) > 1:
        return "(" + " AND ".join(_not_to_sql(p, col, base) for p in parts) + ")"
    return _not_to_sql(expr, col, base)


def _not_to_sql(expr: str, col: str, base: str) -> str:
    text = expr.strip()
    if text.upper().startswith("NOT "):
        return f"(NOT {_or_to_sql(text[4:].strip(), col, base)})"
    return _atom_to_sql(text, col, base)


def _atom_to_sql(expr: str, col: str, base: str) -> str:  # noqa: C901 — mirrors _eval_atom ladder
    text = _strip_outer_parens(expr.strip())
    if not text:
        return "TRUE"

    ln = _str_coalesced(col, base, "logName")

    # logName:("a" OR "b")  — substring match on any option (raw or URL-decoded)
    m = re.match(r"^logName:\((.+)\)$", text, re.DOTALL)
    if m:
        options = re.findall(r'"([^"]+)"', m.group(1))
        return "(" + " OR ".join(_logname_contains(ln, opt) for opt in options) + ")" if options else "TRUE"

    # logName:"fragment"
    m = re.match(r'^logName:"([^"]+)"$', text)
    if m:
        return _logname_contains(ln, m.group(1))

    m = re.match(r'^resource\.type="([^"]+)"$', text)
    if m:
        return f"{_str_coalesced(col, base, 'resource.type')} = {_sql_str(m.group(1))}"

    m = re.match(r'^protoPayload\.serviceName="([^"]+)"$', text)
    if m:
        return f"{_str_coalesced(col, base, 'protoPayload.serviceName')} = {_sql_str(m.group(1))}"

    m = re.match(r"^protoPayload\.methodName=\((.+)\)$", text)
    if m:
        options = re.findall(r'"([^"]+)"', m.group(1))
        lhs = _str_coalesced(col, base, "protoPayload.methodName")
        if not options:
            return "FALSE"  # empty IN list: no method matches (mirrors `method in []`)
        return f"{lhs} IN (" + ", ".join(_sql_str(o) for o in options) + ")"

    m = re.match(r'^protoPayload\.methodName="([^"]+)"$', text)
    if m:
        return f"{_str_coalesced(col, base, 'protoPayload.methodName')} = {_sql_str(m.group(1))}"

    m = re.match(r"^severity>=(\w+)$", text)
    if m:
        return f"{_severity_case(col, base)} >= {_severity_rank(m.group(1))}"

    m = re.match(r"^jsonPayload\.(\w+)=\*$", text)
    if m:
        return _present_not_null(col, base, f"jsonPayload.{m.group(1)}")

    # Truthiness forms: Python compares bool(value), whose semantics over arbitrary JSON
    # (numbers, strings, arrays) do not map cleanly to SQL. No real Ventra filter uses these,
    # so we decline and fall back rather than risk a mismatch.
    if re.match(r"^jsonPayload\.(\w+)=(true|false)$", text, re.IGNORECASE):
        raise FilterTranslationError(f"boolean atom not translated: {text!r}")
    if re.match(r"^httpRequest\.(\w+)=(true|false)$", text, re.IGNORECASE):
        raise FilterTranslationError(f"boolean atom not translated: {text!r}")

    m = re.match(r'^resource\.labels\.(\w+)="([^"]+)"$', text)
    if m:
        return f"{_str_coalesced(col, base, f'resource.labels.{m.group(1)}')} = {_sql_str(m.group(2))}"

    m = re.match(r'^resource\.labels\.(\w+):"([^"]+)"$', text)
    if m:
        lhs = _str_coalesced(col, base, f"resource.labels.{m.group(1)}")
        return f"contains({lhs}, {_sql_str(m.group(2))})"

    m = re.match(r"^jsonPayload\.([\w.]+):\*$", text)
    if m:
        return _present_not_null(col, base, f"jsonPayload.{m.group(1)}")

    # Unrecognized clause — fail loud, identically to the Python matcher's _eval_atom. A typo
    # must not translate to SQL TRUE and silently match every record.
    raise UnrecognizedFilterAtom(text)


def _logname_contains(ln_expr: str, fragment: str) -> str:
    """Mirror ``_log_name_matches``: raw fragment OR its URL-decoded form as a substring."""
    decoded = unquote(fragment)
    clauses = [f"contains({ln_expr}, {_sql_str(fragment)})"]
    if decoded != fragment:
        clauses.append(f"contains({ln_expr}, {_sql_str(decoded)})")
    return "(" + " OR ".join(clauses) + ")" if len(clauses) > 1 else clauses[0]


# --- window + project-scope predicates (mirror entry_in_window / entry_in_project_scope) ----


def _timestamp_expr(col: str, base: str) -> str:
    ts = _str_coalesced(col, base, "timestamp")
    # Cloud Logging timestamps are UTC ("…Z", up to nanosecond precision). Strip the zone marker
    # and cast to a *naive* UTC TIMESTAMP: micro precision (truncating ns exactly like
    # datetime.fromisoformat), unparseable/absent -> NULL -> row included (mirrors
    # entry_timestamp() returning None). We deliberately avoid TIMESTAMPTZ, whose DuckDB cast
    # path requires the optional 'pytz' module that Ventra does not depend on.
    return f"TRY_CAST(replace({ts}, 'Z', '') AS TIMESTAMP)"


def _naive_utc_literal(dt: datetime) -> str:
    from datetime import UTC

    return dt.astimezone(UTC).replace(tzinfo=None).isoformat(sep=" ")


def _window_sql(col: str, base: str, start, end) -> str | None:
    if start is None and end is None:
        return None
    ts = _timestamp_expr(col, base)
    bounds = []
    if start is not None:
        bounds.append(f"{ts} >= TIMESTAMP {_sql_str(_naive_utc_literal(start))}")
    if end is not None:
        bounds.append(f"{ts} <= TIMESTAMP {_sql_str(_naive_utc_literal(end))}")
    # Fail closed: NULL (unparseable/missing) timestamp -> excluded from a windowed result,
    # mirroring entry_in_window() now returning False for such rows.
    return f"({ts} IS NOT NULL AND {' AND '.join(bounds)})"


def _timestamp_null_sql(col: str, base: str) -> str:
    """True when the entry's timestamp is missing/unparseable (mirror entry_timestamp() is None)."""
    return f"{_timestamp_expr(col, base)} IS NULL"


def _project_scope_sql(col: str, base: str, project_scope: list[str] | None) -> str | None:
    prefixes = [f"projects/{p.strip()}/" for p in (project_scope or []) if p and p.strip()]
    if not prefixes:
        return None
    ln = _str_coalesced(col, base, "logName")
    # entry_in_project_scope: empty logName is kept; otherwise must start with a scoped prefix.
    likes = " OR ".join(f"starts_with({ln}, {_sql_str(p)})" for p in prefixes)
    return f"({ln} = '' OR {likes})"


def build_entry_where(
    filter_str: str,
    col: str,
    base: str,
    *,
    start=None,
    end=None,
    project_scope: list[str] | None = None,
    include_window: bool = True,
) -> str:
    """Full row predicate: log filter AND window AND project scope (any of which may be absent).

    With ``include_window=False`` the window clause is omitted — used to count rows that pass the
    filter + scope but carry an unparseable timestamp (the fail-closed exclusion count).
    """
    clauses = [filter_to_sql(filter_str, col, base)]
    if include_window:
        window = _window_sql(col, base, start, end)
        if window is not None:
            clauses.append(window)
    scope = _project_scope_sql(col, base, project_scope)
    if scope is not None:
        clauses.append(scope)
    return " AND ".join(c for c in clauses if c and c != "TRUE") or "TRUE"


def validate_gcp_log_filter(filter_str: str) -> None:
    """Raise :class:`UnrecognizedFilterAtom` if the filter contains a clause we don't recognise.

    Walks every atom (no boolean short-circuit, so all clauses are checked). A ``=true/false``
    truthiness form is *recognised* (just not SQL-translatable), so the ``FilterTranslationError``
    it raises is swallowed here — only genuine typos propagate. Intended to run before a read so
    a bad filter fails fast and identically whether or not DuckDB is in use.
    """
    try:
        filter_to_sql(filter_str, "json", "")
    except FilterTranslationError:
        return


# --- runners ------------------------------------------------------------------------------

_LOG = logging.getLogger(__name__)


def _connect() -> Any:
    import duckdb

    con = duckdb.connect()
    # Deterministic row order (belt-and-braces; the reader also ORDER BYs an index) and a
    # bounded footprint so a huge spool cannot balloon memory beyond the file itself.
    con.execute("PRAGMA threads=4")
    return con


def duckdb_filter_raw_entries(
    entries: Iterable[dict[str, Any]],
    log_filter: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    project_scope: list[str] | None = None,
    counters: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Return the entries that pass ``log_filter`` + window + scope, in input order.

    Raises :class:`FilterTranslationError` when the filter cannot be faithfully translated and
    propagates any DuckDB error — callers catch both and fall back to the Python path. The
    returned objects are the *original* dicts (not re-parsed), so callers apply the untouched
    ``normalize_log_entry`` and downstream shape is unchanged.

    When ``counters`` is provided and a window is set, ``counters['excluded_unparseable_ts']`` is
    incremented by the number of rows that matched the filter + scope but were dropped for having
    an unparseable/missing timestamp (the fail-closed exclusions), so callers can surface a gap.
    """
    rows = list(entries)
    if not rows:
        return []
    where = build_entry_where(log_filter, "json", "e.", start=start, end=end, project_scope=project_scope)
    windowed = start is not None or end is not None
    con = _connect()
    tmp = Path(tempfile.mkstemp(prefix="ventra-dfilter-", suffix=".jsonl")[1])
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            for idx, entry in enumerate(rows):
                fh.write(json.dumps({"i": idx, "e": entry}, default=str))
                fh.write("\n")
        src = f"read_json_objects({_sql_str(str(tmp))}, format='newline_delimited')"
        sql = f"SELECT CAST(json_extract(json, '$.i') AS BIGINT) AS i FROM {src} WHERE {where} ORDER BY i"
        idxs = [r[0] for r in con.execute(sql).fetchall()]

        if counters is not None and windowed:
            fs_where = build_entry_where(
                log_filter,
                "json",
                "e.",
                start=start,
                end=end,
                project_scope=project_scope,
                include_window=False,
            )
            null_ts = _timestamp_null_sql("json", "e.")
            count_sql = f"SELECT count(*) FROM {src} WHERE ({fs_where}) AND {null_ts}"
            excluded = con.execute(count_sql).fetchone()[0]
            if excluded:
                counters["excluded_unparseable_ts"] = counters.get("excluded_unparseable_ts", 0) + int(
                    excluded
                )
        return [rows[i] for i in idxs]
    finally:
        con.close()
        tmp.unlink(missing_ok=True)


class GcpEntryMatcher:
    """Filters raw GCS-export entries — DuckDB fast path, Python fallback — returning the
    normalised survivors in input order.

    One instance per read. It decides up front whether DuckDB can serve this filter (enabled,
    importable, translatable); if a DuckDB error surfaces mid-read it latches to the Python path
    for the remainder and logs once, so a single bad batch can never drop evidence.
    """

    def __init__(
        self,
        log_filter: str,
        start: datetime | None = None,
        end: datetime | None = None,
        project_scope: list[str] | None = None,
        stats: dict[str, Any] | None = None,
    ) -> None:
        self._filter = log_filter or ""
        self._start = start
        self._end = end
        self._scope = project_scope
        self._stats = stats
        self._windowed = start is not None or end is not None
        # Fail loud on a typo'd/unknown clause before reading anything — identically whether or
        # not DuckDB is used (validate_gcp_log_filter is a pure string walk).
        validate_gcp_log_filter(self._filter)
        self._use_duckdb = duckdb_filtering_enabled() and duckdb_available()
        if self._use_duckdb:
            try:
                build_entry_where(
                    self._filter, "json", "e.", start=start, end=end, project_scope=project_scope
                )
            except FilterTranslationError:
                _LOG.info(
                    "gcp duckdb filter: %r not fully translatable; using python path",
                    self._filter,
                )
                self._use_duckdb = False

    @property
    def using_duckdb(self) -> bool:
        return self._use_duckdb

    def _add_excluded_ts(self, n: int) -> None:
        if not n or self._stats is None:
            return
        key = "excluded_unparseable_timestamp"
        self._stats[key] = int(self._stats.get(key, 0)) + int(n)

    def filter_batch(self, raw_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from collector.engine.gcp_log_export import normalize_log_entry

        if self._use_duckdb:
            try:
                counters: dict[str, int] = {}
                matched = duckdb_filter_raw_entries(
                    raw_entries,
                    self._filter,
                    start=self._start,
                    end=self._end,
                    project_scope=self._scope,
                    counters=counters,
                )
                self._add_excluded_ts(counters.get("excluded_unparseable_ts", 0))
                return [normalize_log_entry(e) for e in matched]
            except Exception as exc:  # noqa: BLE001 — any failure => Python path, never drop rows
                self._use_duckdb = False
                _LOG.warning("gcp duckdb filter failed (%s); falling back to python filtering", exc)
        return self._python_filter(raw_entries)

    def _python_filter(self, raw_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from collector.engine.gcp_log_export import (
            entry_in_project_scope,
            entry_in_window,
            entry_timestamp,
            matches_gcp_log_filter,
            normalize_log_entry,
        )

        out: list[dict[str, Any]] = []
        excluded_ts = 0
        for raw in raw_entries:
            entry = normalize_log_entry(raw)
            # Order matches the DuckDB count attribution: a row is only counted as a
            # timestamp exclusion if it would otherwise have been kept (filter + scope pass).
            if not matches_gcp_log_filter(entry, self._filter):
                continue
            if not entry_in_project_scope(entry, self._scope):
                continue
            if self._windowed and entry_timestamp(entry) is None:
                excluded_ts += 1
                continue
            if not entry_in_window(entry, self._start, self._end):
                continue
            out.append(entry)
        self._add_excluded_ts(excluded_ts)
        return out


def duckdb_filter_spool_file(
    spool_path: str | Path,
    log_filter: str,
    *,
    max_records: int | None = None,
    unlimited: bool = False,
    batch_rows: int = 4096,
) -> Iterator[dict[str, Any]]:
    """Stream entries from a JSONL(.gz) spool where each line is one entry, applying ``log_filter``.

    Used by the export/shared spool replayers, whose spools already had window + scope applied at
    fill time, so only the log filter is evaluated here. Rows are streamed (fetchmany) in file
    order so ``max_records`` truncation matches the Python path. Raises/propagates like
    :func:`duckdb_filter_raw_entries`.
    """
    where = filter_to_sql(log_filter, "json", "")
    con = _connect()
    try:
        sql = (
            "SELECT json FROM read_json_objects("
            f"{_sql_str(str(spool_path))}, format='newline_delimited') WHERE {where}"
        )
        cur = con.execute(sql)
        emitted = 0
        while True:
            chunk = cur.fetchmany(batch_rows)
            if not chunk:
                return
            for (raw_json,) in chunk:
                yield json.loads(raw_json)
                emitted += 1
                if not unlimited and max_records is not None and emitted >= max_records:
                    return
    finally:
        con.close()


def replay_spool_with_fallback(
    spool_path: str | Path,
    log_filter: str,
    *,
    max_records: int,
    unlimited: bool,
) -> Iterator[dict[str, Any]]:
    """Yield entries from a JSONL(.gz) spool matching ``log_filter``, DuckDB-first.

    Window/scope were already applied when the spool was filled, so only the log filter runs
    here. If DuckDB is disabled, unavailable, or the filter is untranslatable, the Python loop
    serves the whole read. If a DuckDB *runtime* error surfaces mid-stream, we log and resume on
    the Python path, skipping the rows already emitted so nothing is duplicated or dropped.
    """
    import gzip

    from collector.engine.gcp_log_export import matches_gcp_log_filter

    use = duckdb_filtering_enabled() and duckdb_available()
    if use:
        try:
            filter_to_sql(log_filter, "json", "")  # pre-validate translation (no execution)
        except FilterTranslationError:
            _LOG.info("gcp duckdb spool filter: %r not translatable; using python path", log_filter)
            use = False

    emitted = 0
    if use:
        try:
            for entry in duckdb_filter_spool_file(
                spool_path,
                log_filter,
                max_records=(None if unlimited else max_records),
                unlimited=unlimited,
            ):
                yield entry
                emitted += 1
            return
        except Exception as exc:  # noqa: BLE001 — resume on Python path, skipping emitted rows
            _LOG.warning(
                "gcp duckdb spool filter failed after %d rows (%s); resuming on python path",
                emitted,
                exc,
            )

    seen = 0
    out = 0
    with gzip.open(spool_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            entry = json.loads(line)
            if log_filter.strip() and not matches_gcp_log_filter(entry, log_filter):
                continue
            seen += 1
            if seen <= emitted:
                continue  # already yielded by the DuckDB pass before it failed
            yield entry
            out += 1
            if not unlimited and (emitted + out) >= max_records:
                return
