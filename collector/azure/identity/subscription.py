"""Azure subscription / tenant context collector."""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, AzureClientFactory


class SubscriptionCollector(Collector):
    name = "subscription"
    priority = 1
    description = "Subscription, tenant, region, and operator context."
    required_actions = (
        "Microsoft.Resources/subscriptions/read",
        "Microsoft.Resources/subscriptions/locations/read",
    )

    def collect(self) -> SourceResult:
        cf: AzureClientFactory = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        try:
            identity = cf.identity()
        except Exception as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.ERRORED,
                gaps=[(self.name, GapReason.COLLECTOR_ERROR, str(exc))],
                notes=str(exc),
            )

        regions = self.ctx.regions
        if not regions:
            try:
                regions = cf.enabled_regions()
            except AccessDenied as exc:
                gaps.append(("locations", GapReason.ACCESS_DENIED, exc.message))
                regions = []

        snapshot = {
            "subscription_id": identity.subscription_id,
            "tenant_id": identity.tenant_id,
            "operator_name": identity.principal_name,
            "operator_id": identity.principal_id,
            "operator_type": identity.principal_type,
            "regions_in_scope": regions,
            "display_name": identity.subscription_id,
        }

        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "subscription_id": identity.subscription_id,
                "tenant_id": identity.tenant_id,
                "regions": regions,
                "sha256": wf.sha256,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes="Azure subscription + operator context.",
        )
