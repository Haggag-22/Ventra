"""OAuth2 consent-grant collector — illicit-application persistence.

Illicit OAuth consent is the dominant Entra/M365 persistence technique: an attacker tricks a
user (or admin) into consenting to a malicious app, which then holds standing delegated access
to mail and data without needing the user's password again. This collector enumerates the
tenant's current ``oauth2PermissionGrants`` via Microsoft Graph so the analyst can spot
suspicious apps and over-broad scopes. The *consent events* themselves are captured by the
Entra audit + Unified Audit Log; this is the standing-grant inventory that complements them.
"""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureAccessDenied, AzureServiceNotEnabled

MAX_RECORDS = 200_000


class OAuthConsentCollector(Collector):
    name = "oauth_consent"
    priority = 1
    description = "OAuth2 permission (consent) grants via Microsoft Graph — illicit-app persistence."
    required_actions = ("Directory.Read.All",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []

        records: list[dict] = []
        try:
            for grant in cf.graph_paginate("oauth2PermissionGrants", max_records=MAX_RECORDS):
                records.append(grant)
        except AzureAccessDenied as exc:
            gaps.append(("oauth_consent", GapReason.ACCESS_DENIED, exc.message))
        except AzureServiceNotEnabled as exc:
            gaps.append(("oauth_consent", GapReason.SERVICE_NOT_ENABLED, exc.message))

        files = []
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta({"source": self.name, "records": len(records)})

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("oauth_consent", GapReason.NOT_PRESENT, "No OAuth2 permission grants."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} OAuth2 consent grant(s).",
        )
