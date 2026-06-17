"""Azure Firewall log collector (diagnostic settings → Storage)."""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import SourceResult
from ..common.diagnostics import collect_diagnostic_logs

_RESOURCE_TYPES = ["Microsoft.Network/azureFirewalls"]
_LOG_CATEGORIES = [
    "AzureFirewallApplicationRule",
    "AzureFirewallNetworkRule",
    "AzureFirewallDnsProxy",
]


class AzureFirewallCollector(Collector):
    name = "azure_firewall"
    priority = 1
    description = "Azure Firewall application/network/DNS proxy logs from Storage diagnostics."
    required_actions = (
        "Microsoft.Network/azureFirewalls/read",
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_diagnostic_logs(
            self, resource_types=_RESOURCE_TYPES, log_categories=_LOG_CATEGORIES
        )
