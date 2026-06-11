"""AWS Config collector (Tier 2).

Config's recorder state tells you whether resource-change history was being captured (a
defense-evasion tell when it's off), and the configuration timeline is invaluable for
"what changed during the window". Here we capture recorder/delivery state and compliance;
per-resource history is pulled on demand by the analyst given specific resource IDs.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class ConfigCollector(Collector):
    name = "config"
    tier = 2
    description = "AWS Config recorder state and compliance findings."
    required_actions = (
        "config:DescribeConfigurationRecorders",
        "config:DescribeDeliveryChannels",
        "config:DescribeComplianceByConfigRule",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        recorders: list[dict] = []
        compliance: list[dict] = []
        enabled_anywhere = False

        for region in self.ctx.regions:
            try:
                recs = cf.call("config", region, "describe_configuration_recorders").get(
                    "ConfigurationRecorders", []
                )
                channels = cf.call("config", region, "describe_delivery_channels").get(
                    "DeliveryChannels", []
                )
                if recs:
                    enabled_anywhere = True
                    recorders.append({"region": region, "recorders": recs, "channels": channels})
            except AccessDenied as exc:
                gaps.append(("config", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue
            except ClientError as exc:
                gaps.append(("config", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
                continue
            # Compliance is pulled separately so a failure here can't discard the
            # recorder-state evidence above. Paginated — a single call returns only the
            # first page (~10 rules).
            try:
                for c in cf.paginate(
                    "config",
                    region,
                    "describe_compliance_by_config_rule",
                    "ComplianceByConfigRules",
                ):
                    c["_harbor_region"] = region
                    compliance.append(c)
            except AccessDenied as exc:
                gaps.append(("config_compliance", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except ServiceNotEnabled:
                continue
            except ClientError as exc:
                gaps.append(("config_compliance", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
                continue

        if not enabled_anywhere and not compliance:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("config", GapReason.SERVICE_NOT_ENABLED, "No Config recorder in scope.")],
                notes="AWS Config not recording in any in-scope region.",
            )

        files = [
            self.write_json({"recorders": recorders}, "config.json"),
        ]
        if compliance:
            files.append(self.write_jsonl(compliance, "events.jsonl.gz"))
        self.write_meta({"source": self.name, "recorders": len(recorders), "compliance": len(compliance)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(compliance),
            gaps=gaps,
            notes=f"Config recording in {len(recorders)} region(s).",
        )
