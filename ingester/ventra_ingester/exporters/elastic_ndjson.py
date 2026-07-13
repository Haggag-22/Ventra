"""Export ingested case events to NDJSON for a downstream SIEM.

Three targets share one DuckDB read path and only differ in how a row is shaped on the way
out — this is a file-download export, never a live push (see console/backend/app/__init__.py:
the console makes no outbound network calls; a Splunk/Elastic forwarder or manual bulk-load
picks the file up from disk, Ventra never POSTs to a SIEM itself):

* ``elastic``  — ECS-shaped NDJSON (see ``schemas/unified-event.schema.json``): nested
  ``event.*``, ``cloud.*``, ``user.*``, ``source.*``, etc., plus ``ventra.*`` bookkeeping
  and verbatim ``raw``. Ships a starting index template. Customers who want a different
  layout remapping in Logstash/Filebeat/ingest pipelines — Ventra's Elastic export is ECS.
* ``splunk``   — HTTP Event Collector (HEC) batch envelope
  (``{"time", "host", "source", "sourcetype", "event"}``) with the ``event`` payload
  mapped to Splunk CIM field names (``action``, ``src``, ``user``, ``dest``, …), plus
  ``ventra_*`` bookkeeping and verbatim ``raw``. Customers who want a different layout
  remap in props/transforms — Ventra's Splunk export is CIM.
* ``ndjson``   — no shaping at all: the normalized flat event fields as-is, one per line, for
  any other JSON-log pipeline (Sumo Logic, Datadog, Chronicle, a custom pipeline, ...).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterator

import duckdb

# Parquet stores list/dict columns as JSON strings (see UnifiedEvent.to_row).
_JSON_COLUMNS = frozenset(
    {"event_category", "related_ip", "related_user", "related_resource", "raw"}
)
_BATCH_SIZE = 5000

_TARGETS = frozenset({"elastic", "splunk", "ndjson"})


def _parse_json_columns(doc: dict[str, Any]) -> None:
    for col in _JSON_COLUMNS:
        val = doc.get(col)
        if isinstance(val, str) and val:
            try:
                doc[col] = json.loads(val)
            except json.JSONDecodeError:
                pass


def _base_doc(cols: list[str], row: tuple[Any, ...]) -> dict[str, Any]:
    doc: dict[str, Any] = dict(zip(cols, row, strict=True))
    _parse_json_columns(doc)
    return doc


def _nonempty(value: Any) -> bool:
    return value is not None and value != "" and value != []


def _put(obj: dict[str, Any], key: str, value: Any) -> None:
    if _nonempty(value):
        obj[key] = value


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _shape_elastic(doc: dict[str, Any], *, case_id: str, source: str) -> dict[str, Any]:
    """Project a flat UnifiedEvent row into ECS nested fields for Elastic ingest."""
    ts = doc.get("timestamp") or ""
    out: dict[str, Any] = {
        "@timestamp": ts,
        "event": {},
        "cloud": {},
        "ventra": {
            "case_id": case_id or doc.get("case_id") or "",
            "source": source or doc.get("ventra_source") or "",
        },
    }

    event = out["event"]
    _put(event, "kind", doc.get("event_kind"))
    category = doc.get("event_category")
    event["category"] = category if isinstance(category, list) else []
    _put(event, "action", doc.get("event_action"))
    _put(event, "outcome", doc.get("event_outcome"))
    _put(event, "severity", doc.get("event_severity"))
    _put(event, "provider", doc.get("event_provider"))

    cloud = out["cloud"]
    _put(cloud, "provider", doc.get("cloud_provider"))
    _put(cloud, "region", doc.get("cloud_region"))
    account_id = doc.get("cloud_account")
    if _nonempty(account_id):
        cloud["account"] = {"id": account_id}
    service_name = doc.get("cloud_service")
    if _nonempty(service_name):
        cloud["service"] = {"name": service_name}

    user: dict[str, Any] = {}
    _put(user, "name", doc.get("user_name"))
    _put(user, "id", doc.get("user_id"))
    _put(user, "arn", doc.get("user_arn"))
    _put(user, "type", doc.get("user_type"))
    if user:
        out["user"] = user

    source_obj: dict[str, Any] = {}
    _put(source_obj, "ip", doc.get("source_ip"))
    country = doc.get("source_country")
    if _nonempty(country):
        source_obj["geo"] = {"country_iso_code": country}
    asn = _as_int(doc.get("source_asn"))
    if asn is not None:
        source_obj["as"] = {"number": asn}
    if source_obj:
        out["source"] = source_obj

    destination: dict[str, Any] = {}
    _put(destination, "ip", doc.get("dest_ip"))
    dest_port = _as_int(doc.get("dest_port"))
    if dest_port is not None:
        destination["port"] = dest_port
    dest_bytes = _as_int(doc.get("dest_bytes"))
    if dest_bytes is not None:
        destination["bytes"] = dest_bytes
    if destination:
        out["destination"] = destination

    resource: dict[str, Any] = {}
    _put(resource, "type", doc.get("resource_type"))
    _put(resource, "id", doc.get("resource_id"))
    _put(resource, "arn", doc.get("resource_arn"))
    if resource:
        out["resource"] = resource

    user_agent: dict[str, Any] = {}
    _put(user_agent, "original", doc.get("ua_original"))
    _put(user_agent, "category", doc.get("ua_category"))
    if user_agent:
        out["user_agent"] = user_agent

    related: dict[str, Any] = {}
    for flat_key, ecs_key in (
        ("related_ip", "ip"),
        ("related_user", "user"),
        ("related_resource", "resource"),
    ):
        val = doc.get(flat_key)
        if isinstance(val, list) and val:
            related[ecs_key] = val
    if related:
        out["related"] = related

    _put(out, "message", doc.get("message"))

    ventra = out["ventra"]
    if doc.get("parser_version"):
        ventra["parser_version"] = doc["parser_version"]

    raw = doc.get("raw")
    if isinstance(raw, dict):
        out["raw"] = raw
    elif raw is not None:
        out["raw"] = raw

    return out


def _epoch_seconds(ts: Any) -> float | None:
    if not ts:
        return None
    from datetime import datetime

    text = str(ts).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _shape_splunk(doc: dict[str, Any], *, case_id: str, source: str) -> dict[str, Any]:
    """HEC envelope with a CIM-normalized ``event`` payload.

    Shared CIM fields (Authentication / Change / Network_Traffic / etc.) are populated from
    the flat UnifiedEvent row. Ventra bookkeeping uses ``ventra_*`` prefixes; the original
    record is preserved under ``raw``.
    """
    event: dict[str, Any] = {}

    _put(event, "action", doc.get("event_action"))
    _put(event, "status", doc.get("event_outcome"))
    _put(event, "severity", doc.get("event_severity"))
    category = doc.get("event_category")
    if isinstance(category, list) and category:
        event["category"] = category

    _put(event, "user", doc.get("user_name"))
    _put(event, "user_id", doc.get("user_id"))
    # CIM has no ARN field; keep under a stable ventra_* name for pivots.
    _put(event, "ventra_user_arn", doc.get("user_arn"))
    _put(event, "user_type", doc.get("user_type"))

    src_ip = doc.get("source_ip")
    if _nonempty(src_ip):
        event["src"] = src_ip
        event["src_ip"] = src_ip
    _put(event, "src_country", doc.get("source_country"))
    asn = _as_int(doc.get("source_asn"))
    if asn is not None:
        event["src_asn"] = asn

    dest_ip = doc.get("dest_ip")
    if _nonempty(dest_ip):
        event["dest"] = dest_ip
        event["dest_ip"] = dest_ip
    dest_port = _as_int(doc.get("dest_port"))
    if dest_port is not None:
        event["dest_port"] = dest_port
    dest_bytes = _as_int(doc.get("dest_bytes"))
    if dest_bytes is not None:
        event["bytes_out"] = dest_bytes

    _put(event, "app", doc.get("cloud_service") or doc.get("event_provider"))
    provider = doc.get("cloud_provider")
    service = doc.get("cloud_service")
    if _nonempty(provider) and _nonempty(service):
        event["vendor_product"] = f"{provider}:{service}"
    elif _nonempty(doc.get("event_provider")):
        event["vendor_product"] = doc["event_provider"]
    elif _nonempty(provider):
        event["vendor_product"] = provider

    _put(event, "ventra_cloud_provider", provider)
    _put(event, "ventra_cloud_account", doc.get("cloud_account"))
    _put(event, "ventra_cloud_region", doc.get("cloud_region"))

    # Prefer resource type; fall back to event kind for object_category.
    _put(event, "object_category", doc.get("resource_type") or doc.get("event_kind"))
    _put(event, "object_id", doc.get("resource_id"))
    _put(event, "object", doc.get("resource_arn"))

    _put(event, "http_user_agent", doc.get("ua_original"))
    _put(event, "ventra_ua_category", doc.get("ua_category"))
    _put(event, "message", doc.get("message"))

    for flat_key, cim_key in (
        ("related_ip", "ventra_related_ip"),
        ("related_user", "ventra_related_user"),
        ("related_resource", "ventra_related_resource"),
    ):
        val = doc.get(flat_key)
        if isinstance(val, list) and val:
            event[cim_key] = val

    event["ventra_case_id"] = case_id or doc.get("case_id") or ""
    event["ventra_source"] = source or doc.get("ventra_source") or ""
    if doc.get("parser_version"):
        event["ventra_parser_version"] = doc["parser_version"]

    raw = doc.get("raw")
    if raw is not None:
        event["raw"] = raw

    stype = f"ventra:{source or doc.get('ventra_source') or 'event'}"
    envelope: dict[str, Any] = {
        "source": stype,
        "sourcetype": stype,
        "event": event,
    }
    host = case_id or doc.get("case_id")
    if host:
        envelope["host"] = host
    epoch = _epoch_seconds(doc.get("timestamp"))
    if epoch is not None:
        envelope["time"] = epoch
    return envelope


def _shape_ndjson(doc: dict[str, Any], *, case_id: str, source: str) -> dict[str, Any]:
    del case_id, source
    return doc


_SHAPERS: dict[str, Callable[..., dict[str, Any]]] = {
    "elastic": _shape_elastic,
    "splunk": _shape_splunk,
    "ndjson": _shape_ndjson,
}

_FORMAT_NAMES: dict[str, str] = {
    "elastic": "elastic-ecs-ndjson",
    "splunk": "splunk-cim-hec-ndjson",
    "ndjson": "ndjson",
}

# Starting-point ECS mappings for direct bulk load (operators may extend / replace).
_ELASTIC_INDEX_TEMPLATE: dict[str, Any] = {
    "index_patterns": ["ventra-*"],
    "template": {
        "settings": {
            "index.number_of_shards": 1,
            "index.number_of_replicas": 0,
        },
        "mappings": {
            "dynamic": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "message": {"type": "text"},
                "ventra": {
                    "properties": {
                        "case_id": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "parser_version": {"type": "keyword"},
                    }
                },
                "event": {
                    "properties": {
                        "action": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "kind": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "provider": {"type": "keyword"},
                    }
                },
                "user": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "id": {"type": "keyword"},
                        "arn": {"type": "keyword"},
                        "type": {"type": "keyword"},
                    }
                },
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "geo": {
                            "properties": {
                                "country_iso_code": {"type": "keyword"},
                            }
                        },
                        "as": {
                            "properties": {
                                "number": {"type": "long"},
                            }
                        },
                    }
                },
                "destination": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "long"},
                        "bytes": {"type": "long"},
                    }
                },
                "cloud": {
                    "properties": {
                        "provider": {"type": "keyword"},
                        "region": {"type": "keyword"},
                        "account": {
                            "properties": {
                                "id": {"type": "keyword"},
                            }
                        },
                        "service": {
                            "properties": {
                                "name": {"type": "keyword"},
                            }
                        },
                    }
                },
                "resource": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "id": {"type": "keyword"},
                        "arn": {"type": "keyword"},
                    }
                },
                "user_agent": {
                    "properties": {
                        "original": {"type": "keyword"},
                        "category": {"type": "keyword"},
                    }
                },
                "related": {
                    "properties": {
                        "ip": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "resource": {"type": "keyword"},
                    }
                },
                "raw": {"type": "object", "enabled": False},
            },
        },
    },
    "priority": 200,
    "_meta": {
        "description": "Ventra Elastic export — ECS-shaped IR events (schemas/unified-event.schema.json)",
    },
}

_SPLUNK_INSTRUCTIONS = """\
# Loading this export into Splunk

Each `*.ndjson` file is one event per line in the HTTP Event Collector (HEC) batch envelope
shape: `{"time", "host", "source", "sourcetype", "event"}`. The `event` object uses Splunk
**CIM** field names (`action`, `status`, `user`, `src`/`src_ip`, `dest`/`dest_ip`,
`dest_port`, `app`, `vendor_product`, `object`/`object_id`/`object_category`,
`http_user_agent`, `severity`, …) plus `ventra_*` bookkeeping and verbatim `raw`.
Customers who need a different layout remap in props/transforms — Ventra never sends these
events over the network itself.

## Option A — replay to a HEC endpoint you control

    curl -k "$SPLUNK_HEC_URL/services/collector/event" \\
      -H "Authorization: Splunk $HEC_TOKEN" \\
      --data-binary @cloudtrail.ndjson

HEC accepts newline-delimited JSON events in one request body, so the file can be POSTed as-is
(split into smaller batches first if your HEC max-content-length is lower than the file size).

## Option B — forwarder monitor (no HEC token needed)

Point a Universal/Heavy Forwarder monitor stanza at this directory and set a sourcetype that
parses JSON and promotes CIM fields, e.g. in `props.conf`:

    [ventra_export]
    KV_MODE = json
    INDEXED_EXTRACTIONS = json
    TIME_PREFIX = "time":\\s*
    MAX_TIMESTAMP_LOOKAHEAD = 20

Tag / accelerate against the Authentication, Change, or Network Traffic data models as
appropriate for your sourcetypes. This is a starting point, not a certified Splunk add-on.
"""


def _validate_target(target: str) -> None:
    if target not in _TARGETS:
        raise ValueError(f"Unknown export target {target!r}; expected one of {sorted(_TARGETS)}")


def _iter_source_rows(
    con: duckdb.DuckDBPyConnection,
    parquet: Path,
    source: str,
    *,
    since: str | None,
    until: str | None,
) -> Iterator[tuple[list[str], tuple[Any, ...]]]:
    path_sql = str(parquet).replace("'", "''")
    clauses = ["ventra_source = ?"]
    params: list[Any] = [source]
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("timestamp <= ?")
        params.append(until)
    where = " AND ".join(clauses)
    # No ORDER BY — SIEM bulk-load does not require timestamp order, and sorting
    # multi-million-event cases can monopolize CPU for minutes.
    cur = con.execute(
        f"SELECT * FROM read_parquet('{path_sql}') WHERE {where}",
        params,
    )
    cols = [d[0] for d in cur.description]
    while True:
        rows = cur.fetchmany(_BATCH_SIZE)
        if not rows:
            break
        for row in rows:
            yield cols, row


def export_ndjson(
    case_dir: Path,
    out_dir: Path,
    *,
    target: str = "elastic",
    sources: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Path]:
    """Write one NDJSON file per ``ventra_source`` under ``out_dir``, shaped for ``target``.

    Rows are streamed in batches so large cases do not load all events into memory.
    ``sources`` restricts which source streams are exported (default: every source present in
    the case); ``since``/``until`` are inclusive ISO-8601 bounds applied to ``timestamp``,
    pushed into the DuckDB query rather than filtered in Python. Returns a mapping of source
    name to output file path.
    """
    _validate_target(target)
    shape = _SHAPERS[target]

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
    # Progress bars on stderr freeze/interfere with uvicorn --reload logs during long exports.
    try:
        con.execute("SET enable_progress_bar=false")
    except Exception:  # noqa: BLE001
        pass
    path_sql = str(parquet).replace("'", "''")
    all_sources = [
        row[0]
        for row in con.execute(
            f"SELECT DISTINCT ventra_source FROM read_parquet('{path_sql}') ORDER BY 1"
        ).fetchall()
    ]
    wanted = set(sources) if sources else None
    export_sources = [s for s in all_sources if wanted is None or s in wanted]

    written: dict[str, Path] = {}
    event_counts: dict[str, int] = {}
    for source in export_sources:
        safe = source.replace("/", "_").replace(" ", "_") or "unknown"
        out_path = out_dir / f"{safe}.ndjson"
        count = 0
        with out_path.open("w", encoding="utf-8") as fh:
            for cols, row in _iter_source_rows(con, parquet, source, since=since, until=until):
                doc = _base_doc(cols, row)
                shaped = shape(doc, case_id=case_id, source=source)
                fh.write(json.dumps(shaped, default=str, separators=(",", ":")) + "\n")
                count += 1
        written[source] = out_path
        event_counts[source] = count

    if target == "elastic":
        (out_dir / "elastic-index-template.json").write_text(
            json.dumps(_ELASTIC_INDEX_TEMPLATE, indent=2), encoding="utf-8"
        )
    elif target == "splunk":
        (out_dir / "splunk-loading-instructions.md").write_text(
            _SPLUNK_INSTRUCTIONS, encoding="utf-8"
        )

    meta: dict[str, Any] = {
        "case_id": case_id,
        "format": _FORMAT_NAMES[target],
        "target": target,
        "sources": sorted(written.keys()),
        "files": {k: v.name for k, v in written.items()},
        "event_counts": event_counts,
        "total_events": sum(event_counts.values()),
    }
    if sources:
        meta["source_filter"] = sorted(wanted)  # type: ignore[arg-type]
    if since:
        meta["since"] = since
    if until:
        meta["until"] = until
    (out_dir / "export-manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return written


def export_elastic_ndjson(case_dir: Path, out_dir: Path) -> dict[str, Path]:
    """Export ECS-shaped NDJSON for Elastic; backed by :func:`export_ndjson`."""
    return export_ndjson(case_dir, out_dir, target="elastic")
