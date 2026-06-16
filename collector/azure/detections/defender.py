"""Microsoft Defender for Cloud alerts collector."""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, AzureClientFactory
from ..common.serialize import to_dict


class DefenderCollector(Collector):
    name = "defender"
    priority = 1
    description = "Microsoft Defender for Cloud security alerts."
    required_actions = (
        "Microsoft.Security/alerts/read",
        "Microsoft.Security/locations/alerts/read",
    )

    def collect(self) -> SourceResult:
        cf: AzureClientFactory = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        alerts: list[dict] = []

        try:
            sec = cf.security()
            for alert in sec.alerts.list():
                item = to_dict(alert)
                alerts.append(item)
        except AccessDenied as exc:
            gaps.append(("defender", GapReason.ACCESS_DENIED, exc.message))
        except Exception as exc:
            msg = str(exc)
            if "AuthorizationFailed" in msg or "403" in msg:
                gaps.append(("defender", GapReason.ACCESS_DENIED, msg))
            else:
                gaps.append(("defender", GapReason.COLLECTOR_ERROR, msg))

        files = [self.write_json({"alert_count": len(alerts)}, "config.json")]
        if alerts:
            files.append(self.write_jsonl(alerts, "events.jsonl.gz"))
        self.write_meta({"source": self.name, "alerts": len(alerts)})

        if not alerts and not gaps:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[
                    (
                        "defender",
                        GapReason.SERVICE_NOT_ENABLED,
                        "Defender for Cloud returned no alerts (may be disabled or no findings).",
                    )
                ],
                notes="No Defender alerts in scope.",
            )

        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED if alerts else SourceStatus.EMPTY,
            files=files,
            record_count=len(alerts),
            gaps=gaps,
            notes=f"{len(alerts)} Defender alert(s).",
        )
