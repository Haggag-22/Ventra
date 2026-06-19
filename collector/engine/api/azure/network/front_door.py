"""Azure Front Door access + WAF log collector (diagnostic settings → Storage)."""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import SourceResult
from ..common.diagnostics import collect_diagnostic_logs

_RESOURCE_TYPES = [
    "Microsoft.Network/frontDoors",
    "Microsoft.Cdn/profiles",
]
_LOG_CATEGORIES = [
    "FrontdoorAccessLog",
    "FrontDoorAccessLog",
    "FrontdoorWebApplicationFirewallLog",
    "FrontDoorWebApplicationFirewallLog",
    "AccessLog",
    "WAFLog",
]


class FrontDoorCollector(Collector):
    name = "front_door"
    priority = 1
    description = "Front Door (classic + AFD) access and WAF logs from Storage diagnostics."
    required_actions = (
        "Microsoft.Network/frontDoors/read",
        "Microsoft.Cdn/profiles/read",
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_diagnostic_logs(
            self, resource_types=_RESOURCE_TYPES, log_categories=_LOG_CATEGORIES
        )
