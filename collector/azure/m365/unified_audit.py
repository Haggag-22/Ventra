"""Microsoft 365 Unified Audit Log collector — the BEC backbone.

The UAL is the "CloudTrail of Microsoft 365": user / admin / app / mailbox / SharePoint
activity across the tenant, including ``MailItemsAccessed`` (which mail an attacker actually
read — the key exfil-scoping artifact in Business Email Compromise). Pulled via the Office
365 Management Activity API content-blob model across the critical content types.

Read-only contract: the Management API content feed must already be enabled in the tenant.
If a content type's feed is off, Ventra records a Log-Coverage gap rather than starting it
(starting a feed is a tenant mutation, which the collector must never do).

Ingestion latency: UAL events can lag ingestion by up to ~30 minutes (longer for some
workloads). A window whose end is within that lag is flagged as possibly-incomplete in the
collector notes/meta — not silently treated as "no activity".
"""

from __future__ import annotations

from datetime import UTC, datetime

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import window_bounds

# Management Activity API serves ~7 days of history.
DEFAULT_WINDOW_DAYS = 7
MAX_RECORDS = 200_000
# Critical content types for IR; AAD + Exchange carry the identity and BEC evidence.
CONTENT_TYPES = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.General",
    "Audit.SharePoint",
    "DLP.All",
)
# Recent events may not be fully ingested yet (UAL lag).
INGEST_LAG_SECONDS = 1800


class UnifiedAuditCollector(Collector):
    name = "unified_audit"
    priority = 1
    description = (
        "Microsoft 365 Unified Audit Log (incl. MailItemsAccessed) via the Office 365 "
        "Management Activity API."
    )
    required_actions = ("ActivityFeed.Read",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        start, end = window_bounds(self.ctx.time_window, DEFAULT_WINDOW_DAYS)

        records: list[dict] = []
        per_type: list[dict] = []
        for content_type in CONTENT_TYPES:
            before = len(records)
            try:
                for rec in cf.management_content(content_type, start, end, max_records=MAX_RECORDS):
                    records.append(rec)
            except AzureAccessDenied as exc:
                gaps.append(("unified_audit", GapReason.ACCESS_DENIED, f"{content_type}: {exc.message}"))
            except AzureServiceNotEnabled as exc:
                # Feed not enabled in the tenant = a logging blind spot, recorded as a gap.
                gaps.append(
                    ("unified_audit", GapReason.LOGGING_NOT_CONFIGURED, f"{content_type}: {exc.message}")
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
                "records": len(records),
                "content_types": per_type,
                "ingestion_lag_warning": lag_warning,
                "window": self.ctx.time_window.to_manifest(),
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("unified_audit", GapReason.NOT_PRESENT, "No UAL events in window."))

        notes = f"{len(records)} unified audit record(s) across {len(CONTENT_TYPES)} content type(s)."
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
