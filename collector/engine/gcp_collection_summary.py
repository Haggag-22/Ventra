"""collection_summary.json — the per-collector coverage record for a GCP run.

Written next to manifest.json in the sealed package and ingested by the IR platform to
render accurate coverage: every SELECTED collector appears exactly once, either
``collected`` (with row counts and the tables/prefixes used) or ``not_collected`` with the
specific reason resolution or collection produced. Nothing is silently dropped — a subset
view deduplicated into its broad stream is reported ``collected`` via that stream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from collector.lib.models import TimeWindow, utcnow_iso

SUMMARY_SCHEMA_VERSION = "1.0.0"
SUMMARY_FILENAME = "collection_summary.json"

STATUS_COLLECTED = "collected"
STATUS_NOT_COLLECTED = "not_collected"


@dataclass
class CollectorOutcome:
    """Final state of one selected collector after resolution + collection."""

    collector: str
    status: str
    strategy_used: str  # bigquery | storage | log_explorer | direct_api | none
    records: int | None = None
    reason: str | None = None
    tables: list[str] = field(default_factory=list)
    collected_via: str | None = None  # broad stream id when deduplicated
    files: list[str] = field(default_factory=list)
    validation_timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "collector": self.collector,
            "status": self.status,
            "strategy_used": self.strategy_used,
            "records": self.records,
        }
        if self.reason:
            out["reason"] = self.reason
        if self.tables:
            out["tables"] = list(self.tables)
        if self.collected_via:
            out["collected_via"] = self.collected_via
        if self.files:
            out["files"] = list(self.files)
        if self.validation_timed_out:
            out["validation_timed_out"] = True
        return out


def build_collection_summary(
    *,
    case_id: str,
    projects: list[str],
    time_window: TimeWindow,
    strategy: str,
    target: str,
    outcomes: list[CollectorOutcome],
    discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "generated_at": utcnow_iso(),
        "cloud": "gcp",
        "case_id": case_id,
        "strategy": strategy,
        "target": target or None,
        "projects": list(projects),
        "window": time_window.to_manifest(),
        "collectors": [o.to_dict() for o in outcomes],
        "totals": {
            "selected": len(outcomes),
            "collected": sum(1 for o in outcomes if o.status == STATUS_COLLECTED),
            "not_collected": sum(1 for o in outcomes if o.status == STATUS_NOT_COLLECTED),
            "records": sum(o.records or 0 for o in outcomes),
        },
    }
    if discovery:
        summary["discovery"] = discovery
    return summary


def write_collection_summary(staging: Path, summary: dict[str, Any]) -> Path:
    path = Path(staging) / SUMMARY_FILENAME
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return path
