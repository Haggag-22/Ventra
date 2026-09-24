"""Azure DNS query / resolver log collector (diagnostic settings → Storage)."""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import SourceResult
from ..common.diagnostics import collect_diagnostic_logs

_RESOURCE_TYPES = [
    "Microsoft.Network/dnsZones",
    "Microsoft.Network/privateDnsZones",
    "Microsoft.Network/dnsResolverEndpoints",
]
_LOG_CATEGORIES = [
    "QueryLogs",
    "AzureDnsQueryLogs",
    "DNSQueryLogs",
]


class DnsCollector(Collector):
    name = "dns"
    priority = 1
    description = "Public/private DNS and DNS private resolver query logs from Storage diagnostics."
    required_actions = (
        "Microsoft.Network/dnsZones/read",
        "Microsoft.Network/privateDnsZones/read",
        "Microsoft.Network/dnsResolverEndpoints/read",
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_diagnostic_logs(
            self, resource_types=_RESOURCE_TYPES, log_categories=_LOG_CATEGORIES
        )
