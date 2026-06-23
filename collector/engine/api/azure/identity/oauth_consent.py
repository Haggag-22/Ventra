"""OAuth2 consent-grant collector — illicit-application persistence.

Illicit OAuth consent is the dominant Entra/M365 persistence technique: an attacker tricks a
user (or admin) into consenting to a malicious app, which then holds standing delegated access
to mail and data without needing the user's password again. This collector enumerates the
tenant's current ``oauth2PermissionGrants`` via Microsoft Graph so the analyst can spot
suspicious apps and over-broad scopes. The *consent events* themselves are captured by the
Entra audit + Unified Audit Log; this is the standing-grant inventory that complements them.
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled

from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS


class OAuthConsentCollector(Collector):
    name = "oauth_consent"
    priority = 1
    description = "OAuth2 permission (consent) grants via Microsoft Graph — illicit-app persistence."
    required_actions = ("Directory.Read.All",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        cap = self.max_records(MAX_RECORDS)

        files = []
        record_count = 0
        with self.open_jsonl("events.jsonl.gz") as writer:
            try:
                for grant in cf.graph_paginate("oauth2PermissionGrants", max_records=cap):
                    writer.write_record(grant)
            except AzureAccessDenied as exc:
                gaps.append(("oauth_consent", GapReason.ACCESS_DENIED, exc.message))
            except AzureServiceNotEnabled as exc:
                gaps.append(("oauth_consent", GapReason.SERVICE_NOT_ENABLED, exc.message))
            record_count = writer.count
            if record_count:
                files.append(writer.finalize())

        self.write_meta({"source": self.name, "records": record_count})

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("oauth_consent", GapReason.NOT_PRESENT, "No OAuth2 permission grants."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} OAuth2 consent grant(s).",
        )
