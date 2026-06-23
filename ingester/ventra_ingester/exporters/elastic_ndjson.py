"""Export ingested case events to Elastic-friendly NDJSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

import duckdb

# Parquet stores list/dict columns as JSON strings (see UnifiedEvent.to_row).
_JSON_COLUMNS = frozenset(
    {"event_category", "related_ip", "related_user", "related_resource", "raw"}
)
# Top-level fields duplicated under ventra.* for direct Elastic ingest.
_VENTRA_FIELDS = frozenset({"case_id", "ventra_source", "event_severity", "parser_version"})
_BATCH_SIZE = 5000


def _parse_json_columns(doc: dict[str, Any]) -> None:
    for col in _JSON_COLUMNS:
        val = doc.get(col)
        if isinstance(val, str) and val:
            try:
                doc[col] = json.loads(val)
            except json.JSONDecodeError:
                pass


def _row_to_doc(
    cols: list[str],
    row: tuple[Any, ...],
    *,
    case_id: str,
    source: str,
) -> dict[str, Any]:
    doc: dict[str, Any] = dict(zip(cols, row, strict=True))
    _parse_json_columns(doc)

    ts = doc.get("timestamp")
    if ts:
        doc["@timestamp"] = ts

    ventra: dict[str, Any] = {
        "case_id": case_id or doc.get("case_id") or "",
        "source": source or doc.get("ventra_source") or "",
    }
    if doc.get("event_severity"):
        ventra["severity"] = doc["event_severity"]
    if doc.get("parser_version"):
        ventra["parser_version"] = doc["parser_version"]
    doc["ventra"] = ventra

    for key in _VENTRA_FIELDS:
        doc.pop(key, None)

    return doc


def _iter_source_rows(
    con: duckdb.DuckDBPyConnection,
    parquet: Path,
    source: str,
) -> Iterator[tuple[list[str], tuple[Any, ...]]]:
    path_sql = str(parquet).replace("'", "''")
    cur = con.execute(
        f"SELECT * FROM read_parquet('{path_sql}') WHERE ventra_source = ? ORDER BY timestamp",
        [source],
    )
    cols = [d[0] for d in cur.description]
    while True:
        rows = cur.fetchmany(_BATCH_SIZE)
        if not rows:
            break
        for row in rows:
            yield cols, row


def export_elastic_ndjson(case_dir: Path, out_dir: Path) -> dict[str, Path]:
    """Write one NDJSON file per ``ventra_source`` under ``out_dir``.

    Rows are streamed in batches so large cases do not load all events into memory.
    Returns a mapping of source name to output file path.
    """
    case_dir = Path(case_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    parquet = case_dir / "events.parquet"
    if not parquet.is_file():
        raise FileNotFoundError(f"No events.parquet in {case_dir}")

    manifest_path = case_dir / "manifest.json"
    case_id = ""
    if manifest_path.is_file():
        case_id = str(json.loads(manifest_path.read_text(encoding="utf-8")).get("case_id") or "")

    con = duckdb.connect()
    path_sql = str(parquet).replace("'", "''")
    sources = [
        row[0]
        for row in con.execute(
            f"SELECT DISTINCT ventra_source FROM read_parquet('{path_sql}') ORDER BY 1"
        ).fetchall()
    ]

    written: dict[str, Path] = {}
    event_counts: dict[str, int] = {}
    for source in sources:
        safe = source.replace("/", "_").replace(" ", "_") or "unknown"
        out_path = out_dir / f"{safe}.ndjson"
        count = 0
        with out_path.open("w", encoding="utf-8") as fh:
            for cols, row in _iter_source_rows(con, parquet, source):
                doc = _row_to_doc(cols, row, case_id=case_id, source=source)
                fh.write(json.dumps(doc, default=str, separators=(",", ":")) + "\n")
                count += 1
        written[source] = out_path
        event_counts[source] = count

    meta = {
        "case_id": case_id,
        "format": "elastic-ndjson",
        "sources": sorted(written.keys()),
        "files": {k: v.name for k, v in written.items()},
        "event_counts": event_counts,
        "total_events": sum(event_counts.values()),
    }
    (out_dir / "export-manifest.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    return written
