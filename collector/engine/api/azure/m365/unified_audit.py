"""Microsoft 365 Unified Audit Log collector — Management Activity API (near-real-time).

Pulls the last ~7 days via the Office 365 Management Activity API content-blob feeds.
Complements :mod:`unified_audit_search` which uses ``Search-UnifiedAuditLog`` for 90–365 day
lookback. Overlapping Entra sign-in/audit events may also appear here under
``Audit.AzureActiveDirectory`` — prefer ``entra_signin`` / ``entra_audit`` for identity timelines.
"""

from __future__ import annotations

from datetime import UTC, datetime

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import window_bounds
from .ual_common import (
    FEED_ENABLE_RUNBOOK,
    MANAGEMENT_CONTENT_TYPES,
    RETENTION_NOTE,
    feed_gap_detail,
    tag_management_record,
)

# Management Activity API serves ~7 days of history.
DEFAULT_WINDOW_DAYS = 7
MAX_RECORDS = 200_000
INGEST_LAG_SECONDS = 1800


class UnifiedAuditCollector(Collector):
    name = "unified_audit"
    priority = 1
    description = (
        "M365 Unified Audit Log (recent window) via Office 365 Management Activity API feeds."
    )
    required_actions = ("ActivityFeed.Read",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        opts = self.ctx.ual
        gaps: list[tuple[str, GapReason, str]] = []
        cap = self.max_records(MAX_RECORDS)
        start, end = window_bounds(self.ctx.time_window, DEFAULT_WINDOW_DAYS)

        records: list[dict] = []
        per_type: list[dict] = []
        truncated = False
        global_cap_hit = False

        for content_type in MANAGEMENT_CONTENT_TYPES:
            if global_cap_hit:
                break
            before = len(records)
            try:
                for rec in cf.management_content(content_type, start, end, max_records=cap):
                    if opts.operations:
                        op = (rec.get("Operation") or "").lower()
                        if not any(o.lower() in op for o in opts.operations):
                            continue
                    if opts.users:
                        user = (rec.get("UserId") or "").lower()
                        if not any(u.lower() in user for u in opts.users):
                            continue
                    records.append(tag_management_record(rec))
                    if len(records) >= cap:
                        global_cap_hit = True
                        truncated = True
                        break
            except AzureAccessDenied as exc:
                gaps.append(("unified_audit", GapReason.ACCESS_DENIED, f"{content_type}: {exc.message}"))
            except AzureServiceNotEnabled as exc:
                gaps.append(
                    (
                        "unified_audit",
                        GapReason.LOGGING_NOT_CONFIGURED,
                        feed_gap_detail(content_type, exc.message),
                    )
                )
            per_type.append({"content_type": content_type, "records": len(records) - before})

        lag_warning = ""
        if (datetime.now(UTC) - end).total_seconds() < INGEST_LAG_SECONDS:
            lag_warning = (
                "Window end is within the UAL ingestion-lag horizon (~30 min); the most recent "
                "events may not yet be available. Re-collect later for complete coverage."
            )

        files = []
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "acquisition": "management_activity_api",
                "records": len(records),
                "content_types": per_type,
                "truncated": truncated,
                "filters": {
                    "users": opts.users,
                    "operations": opts.operations,
                },
                "retention_note": RETENTION_NOTE,
                "feed_runbook": FEED_ENABLE_RUNBOOK,
                "ingestion_lag_warning": lag_warning,
                "window": self.ctx.time_window.to_manifest(),
                "overlap_note": (
                    "Entra sign-in and directory audit collectors are authoritative for "
                    "authentication and directory-change timelines; UAL AAD workload may duplicate."
                ),
            }
        )

        if truncated:
            gaps.append(
                (
                    "unified_audit",
                    GapReason.NOT_PRESENT,
                    f"Collection stopped at {cap:,} records — data may be truncated. "
                    "Narrow --since/--until or use --ual-users / --ual-operations.",
                )
            )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("unified_audit", GapReason.NOT_PRESENT, "No UAL events in window."))

        notes = (
            f"{len(records)} unified audit record(s) via Management API "
            f"across {len(MANAGEMENT_CONTENT_TYPES)} content type(s)."
        )
        if truncated:
            notes += f" Truncated at {cap:,} records."
        if lag_warning:
            notes += " " + lag_warning
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=notes,
        )
