"""VNet flow-log collector — the primary Azure network-flow source.

Captures L3/L4 flows (5-tuple, allow/deny, bytes) for resources in a VNet, independent of any
NSG, from the Storage account the flow log delivers to. This is the exfiltration / lateral-
movement lens. Where no VNet flow log is enabled, a Log-Coverage gap is recorded.
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import SourceResult
from .flow_common import collect_flow_logs, flatten_vnet_record


class VNetFlowCollector(Collector):
    name = "vnet_flow"
    priority = 1
    description = "VNet flow logs (L3/L4 5-tuple, allow/deny, bytes) from the delivery Storage account."
    required_actions = (
        "Microsoft.Network/networkWatchers/flowLogs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_flow_logs(self, flow_type="vnet", flatten=flatten_vnet_record)
