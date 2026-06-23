"""Entra ID sign-in logs collector.

Sign-in logs are the Azure equivalent of the authentication backbone — interactive and
non-interactive auth, MFA, conditional-access verdicts, risky sign-ins, and the source
IP/location/device behind each. Pulled via Microsoft Graph ``auditLogs/signIns``.

Sign-in log access requires an Entra ID P1/P2 license; on a free/Office-365 tenant Graph
rejects the endpoint. That is recorded as a gap (a visibility limit is evidence), not an error.
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import graph_time_filter, window_bounds

# Graph sign-in logs retain ~30 days on Entra P1.
DEFAULT_WINDOW_DAYS = 30
MAX_RECORDS = 200_000


class EntraSignInCollector(Collector):
    name = "entra_signin"
    priority = 1
    description = "Entra ID sign-in logs (interactive + non-interactive) via Microsoft Graph."
    required_actions = ("AuditLog.Read.All", "Directory.Read.All")

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        start, end = window_bounds(self.ctx.time_window, DEFAULT_WINDOW_DAYS)
        params = {
            "$filter": graph_time_filter("createdDateTime", start, end),
            "$top": 1000,
        }
        cap = self.max_records(MAX_RECORDS)

        files = []
        record_count = 0
        with self.open_jsonl("events.jsonl.gz") as writer:
            try:
                for ev in cf.graph_paginate("auditLogs/signIns", params=params, max_records=cap):
                    writer.write_record(ev)
            except AzureAccessDenied as exc:
                gaps.append(("entra_signin", GapReason.ACCESS_DENIED, exc.message))
            except AzureServiceNotEnabled as exc:
                gaps.append(
                    (
                        "entra_signin",
                        GapReason.SERVICE_NOT_ENABLED,
                        f"Sign-in logs unavailable (Entra ID P1/P2 required?): {exc.message}",
                    )
                )
            record_count = writer.count
            if record_count:
                files.append(writer.finalize())

        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "window": self.ctx.time_window.to_manifest(),
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif gaps:
            status = SourceStatus.EMPTY
        else:
            status = SourceStatus.EMPTY
            gaps.append(("entra_signin", GapReason.NOT_PRESENT, "No sign-in events in window."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} sign-in event(s).",
        )
