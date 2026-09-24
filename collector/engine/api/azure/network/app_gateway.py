"""Application Gateway + WAF log collector (diagnostic settings → Storage)."""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import SourceResult
from ..common.diagnostics import collect_diagnostic_logs

_RESOURCE_TYPES = ["Microsoft.Network/applicationGateways"]
_LOG_CATEGORIES = [
    "ApplicationGatewayAccessLog",
    "ApplicationGatewayPerformanceLog",
    "ApplicationGatewayFirewallLog",
]


class AppGatewayCollector(Collector):
    name = "app_gateway"
    priority = 1
    description = "Application Gateway access, performance, and WAF logs from Storage diagnostics."
    required_actions = (
        "Microsoft.Network/applicationGateways/read",
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_diagnostic_logs(
            self, resource_types=_RESOURCE_TYPES, log_categories=_LOG_CATEGORIES
        )
