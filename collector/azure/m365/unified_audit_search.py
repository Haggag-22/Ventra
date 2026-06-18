"""Microsoft 365 Unified Audit Log — Search-UnifiedAuditLog (long lookback).

Uses the Exchange Online Admin API to run ``Search-UnifiedAuditLog`` with adaptive time-window
splitting (Invictus-style) so dense tenants stay under the 5,000 records/call cap. Default
lookback is 90 days (tenant retention may be 180 Standard / 365 Premium).
"""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import window_bounds
from .ual_adaptive import collect_adaptive
from .ual_common import (
    RETENTION_NOTE,
    SEARCH_PERMISSION_RUNBOOK,
)

DEFAULT_WINDOW_DAYS = 90
MAX_RECORDS = 200_000


class UnifiedAuditSearchCollector(Collector):
    name = "unified_audit_search"
    priority = 1
    description = (
        "M365 Unified Audit Log (90-day default) via Search-UnifiedAuditLog + adaptive windows."
    )
    required_actions = ("Exchange.ManageAsApp",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        opts = self.ctx.ual
        gaps: list[tuple[str, GapReason, str]] = []
        start, end = window_bounds(self.ctx.time_window, DEFAULT_WINDOW_DAYS)

        record_types = list(opts.record_types)
        users = list(opts.users)
        operations = list(opts.operations)
        ips = list(opts.ip_addresses)

        def search_window(win_start, win_end):  # noqa: ANN001
            return list(
                cf.search_unified_audit_log(
                    win_start,
                    win_end,
                    users=users or None,
                    operations=operations or None,
                    record_types=record_types or None,
                    ip_addresses=ips or None,
                    max_records=MAX_RECORDS,
                    audit_data_only=opts.audit_data_only,
                )
            )

        try:
            records, warnings = collect_adaptive(
                start,
                end,
                search_window=search_window,
                target_events_per_window=opts.target_events_per_window,
                max_records=MAX_RECORDS,
            )
        except AzureAccessDenied as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("unified_audit_search", GapReason.ACCESS_DENIED, f"{exc.message} {SEARCH_PERMISSION_RUNBOOK}")],
                notes="Search-UnifiedAuditLog denied.",
            )
        except AzureServiceNotEnabled as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[
                    (
                        "unified_audit_search",
                        GapReason.SERVICE_NOT_ENABLED,
                        f"{exc.message} {SEARCH_PERMISSION_RUNBOOK}",
                    )
                ],
                notes="Search-UnifiedAuditLog unavailable.",
            )

        for warn in warnings:
            gaps.append(("unified_audit_search", GapReason.NOT_PRESENT, warn))

        files = []
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "acquisition": "search_unified_audit_log",
                "records": len(records),
                "truncation_warnings": warnings,
                "filters": {
                    "users": users,
                    "operations": operations,
                    "record_types": record_types,
                    "ip_addresses": ips,
                    "target_events_per_window": opts.target_events_per_window,
                    "audit_data_only": opts.audit_data_only,
                },
                "retention_note": RETENTION_NOTE,
                "permission_runbook": SEARCH_PERMISSION_RUNBOOK,
                "window": self.ctx.time_window.to_manifest(),
                "overlap_note": (
                    "Prefer entra_signin / entra_audit for identity timelines; UAL may duplicate "
                    "AzureActiveDirectory workload events."
                ),
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(
                    ("unified_audit_search", GapReason.NOT_PRESENT, "No UAL search results in window.")
                )

        notes = f"{len(records)} unified audit record(s) via Search-UnifiedAuditLog."
        if warnings:
            notes += f" {len(warnings)} truncation warning(s) — see _meta.json."
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=notes,
        )
