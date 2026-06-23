"""Azure Resource Graph inventory snapshot collector.

Runs a bounded Resource Graph query across in-scope subscriptions to capture a point-in-time
resource inventory (id, name, type, location, resource group). Stored as ``snapshot.json``
for the console Resources panel.
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled

INVENTORY_QUERY = """
Resources
| project id, name, type, location, resourceGroup, subscriptionId, tags
| order by type asc, name asc
"""
from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS


class ResourceGraphCollector(Collector):
    name = "resource_graph"
    priority = 2
    description = "Azure Resource Graph inventory snapshot."
    required_actions = ("Microsoft.ResourceGraph/resources/read",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        subscriptions = self.ctx.subscription_ids

        if not subscriptions:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("resource_graph", GapReason.NOT_PRESENT, "No subscriptions in scope.")],
                notes="No subscriptions discovered or specified.",
            )

        cap = self.max_records(MAX_RECORDS)
        try:
            resources = cf.resource_graph_query(
                INVENTORY_QUERY.strip(), subscriptions, max_records=cap
            )
        except AzureAccessDenied as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("resource_graph", GapReason.ACCESS_DENIED, exc.message)],
                notes="Resource Graph query denied.",
            )
        except AzureServiceNotEnabled as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("resource_graph", GapReason.NOT_PRESENT, exc.message)],
                notes="Resource Graph unavailable.",
            )

        snapshot = {"resources": resources, "subscriptions": subscriptions}
        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "resources": len(resources),
                "subscriptions": len(subscriptions),
                "sha256": wf.sha256,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes=f"{len(resources)} resource(s) across {len(subscriptions)} subscription(s).",
        )
