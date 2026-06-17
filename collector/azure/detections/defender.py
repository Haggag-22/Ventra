"""Microsoft Defender for Cloud alerts collector.

Pulls active and historical security alerts across in-scope subscriptions via the
Microsoft.Security/alerts ARM API. Absence of alerts is not an error; a tenant without
Defender enabled or without read permission is recorded as a gap.
"""

from __future__ import annotations

from typing import Any

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureAccessDenied, AzureServiceNotEnabled

MAX_RECORDS = 200_000


class DefenderCollector(Collector):
    name = "defender"
    priority = 1
    description = "Microsoft Defender for Cloud security alerts."
    required_actions = (
        "Microsoft.Security/alerts/read",
        "Microsoft.Security/locations/alerts/read",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        alerts: list[dict[str, Any]] = []
        per_sub: list[dict[str, Any]] = []

        subscriptions = self.ctx.subscription_ids
        if not subscriptions:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("defender", GapReason.NOT_PRESENT, "No subscriptions in scope.")],
                notes="No subscriptions discovered or specified.",
            )

        for sub in subscriptions:
            before = len(alerts)
            try:
                for alert in cf.security_alerts(sub, max_records=MAX_RECORDS - len(alerts)):
                    alert["_ventra_subscription_id"] = sub
                    alerts.append(alert)
                    if len(alerts) >= MAX_RECORDS:
                        break
            except AzureAccessDenied as exc:
                gaps.append(("defender", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
            except AzureServiceNotEnabled as exc:
                gaps.append(("defender", GapReason.SERVICE_NOT_ENABLED, f"{sub}: {exc.message}"))
            per_sub.append({"subscription_id": sub, "alerts": len(alerts) - before})

        files = [self.write_json({"subscriptions": per_sub}, "config.json")]
        if alerts:
            files.append(self.write_jsonl(alerts, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "alerts": len(alerts),
                "subscriptions": per_sub,
            }
        )

        if alerts:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("defender", GapReason.NOT_PRESENT, "No Defender alerts in scope."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(alerts),
            gaps=gaps,
            notes=f"{len(alerts)} Defender alert(s) across {len(subscriptions)} subscription(s).",
        )
