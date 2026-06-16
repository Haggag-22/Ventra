"""Entra ID directory audit logs via Microsoft Graph."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureClientFactory
from ..common.graph import GraphAccessDenied, GraphNotLicensed


class EntraAuditCollector(Collector):
    name = "entra_audit"
    priority = 1
    description = "Entra ID audit logs — directory and application changes."
    required_actions = (
        "AuditLog.Read.All",
        "Directory.Read.All",
    )

    def collect(self) -> SourceResult:
        cf: AzureClientFactory = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        window = self.ctx.time_window
        end = window.until or datetime.now(UTC)
        start = window.since or (end - timedelta(days=30))

        params = {
            "$filter": (
                f"activityDateTime ge {start.strftime('%Y-%m-%dT%H:%M:%SZ')} and "
                f"activityDateTime le {end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            ),
            "$top": "999",
        }

        records: list[dict] = []
        try:
            records = list(cf.graph_pages("/auditLogs/directoryAudits", params=params))
        except GraphAccessDenied as exc:
            gaps.append(("entra_audit", GapReason.ACCESS_DENIED, exc.message))
        except GraphNotLicensed as exc:
            gaps.append(("entra_audit", GapReason.SERVICE_NOT_ENABLED, exc.message))
        except Exception as exc:
            gaps.append(("entra_audit", GapReason.COLLECTOR_ERROR, str(exc)))

        files = [self.write_json({"window": window.to_manifest()}, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta({"source": self.name, "records": len(records)})

        status = SourceStatus.COLLECTED if records else SourceStatus.EMPTY
        if not records and not gaps:
            gaps.append(
                (
                    "entra_audit",
                    GapReason.SERVICE_NOT_ENABLED,
                    "No Entra audit logs returned for the window.",
                )
            )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} audit record(s).",
        )
