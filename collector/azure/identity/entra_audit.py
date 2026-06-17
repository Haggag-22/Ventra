"""Entra ID audit (directory) logs collector.

Directory audit events are the Azure equivalent of IAM control-plane changes: user/group/app
/role modifications, OAuth consent grants, and — critically for persistence detection —
service-principal credential additions. Pulled via Microsoft Graph
``auditLogs/directoryAudits`` (available without a premium license).
"""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import graph_time_filter, window_bounds

# Directory audit logs retain ~30 days.
DEFAULT_WINDOW_DAYS = 30
MAX_RECORDS = 200_000


class EntraAuditCollector(Collector):
    name = "entra_audit"
    priority = 1
    description = "Entra ID directory audit logs (role/app/consent/credential changes) via Graph."
    required_actions = ("AuditLog.Read.All", "Directory.Read.All")

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        start, end = window_bounds(self.ctx.time_window, DEFAULT_WINDOW_DAYS)
        params = {
            "$filter": graph_time_filter("activityDateTime", start, end),
            "$top": 1000,
        }

        records: list[dict] = []
        try:
            for ev in cf.graph_paginate(
                "auditLogs/directoryAudits", params=params, max_records=MAX_RECORDS
            ):
                records.append(ev)
        except AzureAccessDenied as exc:
            gaps.append(("entra_audit", GapReason.ACCESS_DENIED, exc.message))
        except AzureServiceNotEnabled as exc:
            gaps.append(("entra_audit", GapReason.SERVICE_NOT_ENABLED, exc.message))

        files = []
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "window": self.ctx.time_window.to_manifest(),
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("entra_audit", GapReason.NOT_PRESENT, "No directory audit events in window."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} directory audit event(s).",
        )
