"""Azure subscription / tenant context collector.

Captures the environment the rest of the evidence is interpreted against: tenant id/name,
in-scope subscriptions, and the service-principal operator that ran the collection.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled


class SubscriptionCollector(Collector):
    name = "subscription"
    priority = 1
    description = "Tenant, subscription, and operator context."
    required_actions = (
        "Microsoft.Resources/subscriptions/read",
        "Directory.Read.All",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        identity = cf.caller_identity()

        snapshot: dict[str, Any] = {
            "tenant_id": identity.tenant_id,
            "tenant_name": identity.tenant_name,
            "operator_principal": identity.principal,
            "subscriptions_in_scope": self.ctx.subscription_ids,
        }

        try:
            details = cf.subscription_details()
            in_scope = set(self.ctx.subscription_ids)
            snapshot["subscriptions"] = [
                d for d in details if not in_scope or d.get("subscription_id") in in_scope
            ]
        except AzureAccessDenied as exc:
            gaps.append(("subscription", GapReason.ACCESS_DENIED, exc.message))
            snapshot["subscriptions"] = []
        except AzureServiceNotEnabled:
            snapshot["subscriptions"] = []

        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "tenant_id": identity.tenant_id,
                "subscriptions": len(snapshot.get("subscriptions") or []),
                "sha256": wf.sha256,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes="Tenant + subscription context.",
        )
