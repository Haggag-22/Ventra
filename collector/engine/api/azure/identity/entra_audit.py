"""Entra ID audit (directory) logs collector.

Directory audit events are the Azure equivalent of IAM control-plane changes: user/group/app
/role modifications, OAuth consent grants, and — critically for persistence detection —
service-principal credential additions. Pulled via Microsoft Graph
``auditLogs/directoryAudits`` (available without a premium license).
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import graph_entra_audit_filter
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled

# Directory audit logs retain ~30 days.
DEFAULT_WINDOW_DAYS = 30
from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS


class EntraAuditCollector(Collector):
    name = "entra_audit"
    priority = 1
    description = "Entra ID directory audit logs (role/app/consent/credential changes) via Graph."
    required_actions = ("AuditLog.Read.All", "Directory.Read.All")

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        artifact_params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        graph_params = {
            "$filter": graph_entra_audit_filter(artifact_params, start, end),
            "$top": 1000,
        }
        cap = self.max_records(MAX_RECORDS)

        files = []
        record_count = 0
        with self.open_jsonl("events.jsonl.gz") as writer:
            try:
                for ev in cf.graph_paginate(
                    "auditLogs/directoryAudits", params=graph_params, max_records=cap
                ):
                    writer.write_record(ev)
            except AzureAccessDenied as exc:
                gaps.append(("entra_audit", GapReason.ACCESS_DENIED, exc.message))
            except AzureServiceNotEnabled as exc:
                gaps.append(("entra_audit", GapReason.SERVICE_NOT_ENABLED, exc.message))
            record_count = writer.count
            if record_count:
                files.append(writer.finalize())

        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "window": {"since": start.isoformat(), "until": end.isoformat()},
                "artifact_parameters": artifact_params,
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("entra_audit", GapReason.NOT_PRESENT, "No directory audit events in window."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} directory audit event(s).",
        )
