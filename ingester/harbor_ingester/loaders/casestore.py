"""The case store: the on-disk artifact the console reads.

Layout (one directory per case):

    cases/<case_id>/
      manifest.json      copy of the package manifest
      integrity.json     verification report
      summary.json       precomputed Overview stats
      events.parquet     all normalized events (flattened unified schema)
      collection.log     copy of the collector run log
      inventory/*.json   raw snapshots per source

Events are written to Parquet via pyarrow so the console can query them with DuckDB. The
schema is the flattened :class:`UnifiedEvent`. The store is rebuildable: re-ingesting wipes
and recreates ``<case_id>/`` without touching the console.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import pyarrow as pa
import pyarrow.parquet as pq

from ..normalizer.base import UnifiedEvent

# Column order for events.parquet (all strings except the few typed numerics).
_COLUMNS = [
    "timestamp", "event_kind", "event_category", "event_action", "event_outcome",
    "event_severity", "event_provider", "cloud_provider", "cloud_account", "cloud_region",
    "cloud_service", "user_name", "user_id", "user_arn", "user_type", "source_ip",
    "source_country", "source_asn", "dest_ip", "dest_port", "dest_bytes", "resource_type",
    "resource_id", "resource_arn", "ua_original", "ua_category", "related_ip", "related_user",
    "related_resource", "message", "case_id", "harbor_source", "parser_version", "raw",
]

_INT_COLUMNS = {"dest_port", "dest_bytes"}


class CaseStore:
    def __init__(self, root: Path, case_id: str) -> None:
        self.root = Path(root)
        self.case_id = case_id
        self.case_dir = self.root / case_id
        self.inventory_dir = self.case_dir / "inventory"

    def reset(self) -> None:
        if self.case_dir.exists():
            shutil.rmtree(self.case_dir)
        self.inventory_dir.mkdir(parents=True, exist_ok=True)

    # -- writers -------------------------------------------------------------------------

    def write_events(self, events: Iterable[UnifiedEvent]) -> int:
        rows = [ev.to_row() for ev in events]
        count = len(rows)
        columns: dict[str, list[Any]] = {c: [] for c in _COLUMNS}
        for r in rows:
            for c in _COLUMNS:
                columns[c].append(r.get(c))
        arrays = {}
        for c in _COLUMNS:
            if c in _INT_COLUMNS:
                arrays[c] = pa.array(columns[c], type=pa.int64())
            else:
                arrays[c] = pa.array([("" if v is None else str(v)) for v in columns[c]],
                                     type=pa.string())
        table = pa.table(arrays)
        pq.write_table(table, self.case_dir / "events.parquet", compression="zstd")
        return count

    def write_json(self, name: str, obj: Any) -> None:
        (self.case_dir / name).write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")

    def write_inventory(self, source: str, obj: Any) -> None:
        (self.inventory_dir / f"{source}.json").write_text(
            json.dumps(obj, indent=2, default=str), encoding="utf-8"
        )


def build_summary(
    manifest: dict[str, Any],
    integrity: dict[str, Any],
    events: list[UnifiedEvent],
) -> dict[str, Any]:
    """Precompute the Overview panel's stats so the console loads instantly."""
    principals = Counter()
    ips = Counter()
    severities = Counter()
    categories = Counter()
    providers = Counter()
    sensitive = 0
    failures = 0
    timestamps = []

    for ev in events:
        if ev.user_arn or ev.user_name:
            principals[ev.user_arn or ev.user_name] += 1
        if ev.source_ip:
            ips[ev.source_ip] += 1
        severities[ev.event_severity] += 1
        for c in ev.event_category:
            categories[c] += 1
        providers[ev.harbor_source] += 1
        if ev.event_severity in ("high", "critical"):
            sensitive += 1
        if ev.event_outcome == "failure":
            failures += 1
        if ev.timestamp:
            timestamps.append(ev.timestamp)

    timestamps.sort()
    # Collection completeness: expected sources from manifest vs gaps.
    collected = {
        s["name"]
        for s in manifest.get("sources", [])
        if s.get("status") in ("collected", "partial")
    }
    gaps = manifest.get("gaps", [])

    return {
        "case_id": manifest.get("case_id", ""),
        "account_id": manifest.get("account_id", ""),
        "account_alias": manifest.get("account_alias", ""),
        "cloud": manifest.get("cloud", "aws"),
        "regions": manifest.get("regions", []),
        "operator": manifest.get("operator", {}),
        "profile": manifest.get("profile", {}),
        "time_window": manifest.get("time_window", {}),
        "started_at": manifest.get("started_at", ""),
        "completed_at": manifest.get("completed_at", ""),
        "integrity": integrity.get("overall", "unknown"),
        "signature_method": integrity.get("signature_method", ""),
        "totals": {
            "events": len(events),
            "principals": len(principals),
            "source_ips": len(ips),
            "sensitive_actions": sensitive,
            "failures": failures,
        },
        "event_span": {
            "first": timestamps[0] if timestamps else None,
            "last": timestamps[-1] if timestamps else None,
        },
        "by_severity": dict(severities),
        "by_category": dict(categories),
        "by_source": dict(providers),
        "top_principals": principals.most_common(10),
        "top_source_ips": ips.most_common(10),
        "collection": {
            "collected": sorted(collected),
            "gaps": gaps,
        },
    }
