"""NSG flow-log collector — legacy fallback for the network-flow lens.

NSG flow logs are deprecated (no new ones after 2025-06-30, retiring 2027-09-30) but remain
valid evidence in tenants that still run them, so Ventra reads existing ones when present
while VNet flow logs are the primary source. Same flat output shape as ``vnet_flow``.
"""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import SourceResult
from .flow_common import collect_flow_logs, flatten_nsg_record


class NsgFlowCollector(Collector):
    name = "nsg_flow"
    priority = 2
    description = "NSG flow logs (legacy fallback) from the delivery Storage account."
    required_actions = (
        "Microsoft.Network/networkWatchers/flowLogs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_flow_logs(self, flow_type="nsg", flatten=flatten_nsg_record)
