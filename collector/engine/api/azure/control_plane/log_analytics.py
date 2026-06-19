"""Log Analytics diagnostic log collector.

Pulls resource diagnostic logs from Log Analytics workspaces when tenants route diagnostics to
LA instead of Storage. Complements the Storage-blob collectors (firewall, App Gateway, DNS,
storage, Key Vault, AKS) without duplicating events already collected via Storage.
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import SourceResult
from ..common.log_analytics import collect_log_analytics


class LogAnalyticsCollector(Collector):
    name = "log_analytics"
    priority = 2
    description = (
        "Diagnostic logs from Log Analytics workspaces (firewall, App Gateway, DNS, "
        "storage, Key Vault, AKS when routed to LA)."
    )
    required_actions = (
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Resources/subscriptions/resources/read",
        "Microsoft.OperationalInsights/workspaces/read",
        "Microsoft.OperationalInsights/workspaces/query/action",
    )

    def collect(self) -> SourceResult:
        return collect_log_analytics(self)
