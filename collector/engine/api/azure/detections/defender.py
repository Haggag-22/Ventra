"""Microsoft Defender for Cloud alerts collector.

Pulls active and historical security alerts across in-scope subscriptions via the
Microsoft.Security/alerts ARM API. Absence of alerts is not an error; a tenant without
Defender enabled or without read permission is recorded as a gap.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.limits import records_unlimited
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_defender_alerts
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled

from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS


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
        artifact_params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=90)
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

        cap = self.max_records(MAX_RECORDS)
        for sub in subscriptions:
            before = len(alerts)
            try:
                remaining = cap - len(alerts) if not records_unlimited(cap) else cap
                for alert in cf.security_alerts(sub, max_records=remaining):
                    alert["_ventra_subscription_id"] = sub
                    alerts.append(alert)
                    if not records_unlimited(cap) and len(alerts) >= cap:
                        break
            except AzureAccessDenied as exc:
                gaps.append(("defender", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
            except AzureServiceNotEnabled as exc:
                gaps.append(("defender", GapReason.SERVICE_NOT_ENABLED, f"{sub}: {exc.message}"))
            per_sub.append({"subscription_id": sub, "alerts": len(alerts) - before})

        alerts = filter_defender_alerts(alerts, artifact_params)

        files = [self.write_json({"subscriptions": per_sub, "artifact_parameters": artifact_params}, "config.json")]
        if alerts:
            files.append(self.write_jsonl(alerts, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "alerts": len(alerts),
                "subscriptions": per_sub,
                "window": {"since": start.isoformat(), "until": end.isoformat()},
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
