"""Key Vault audit log collector (diagnostic settings → Storage)."""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import SourceResult
from ..common.diagnostics import collect_diagnostic_logs

_RESOURCE_TYPES = ["Microsoft.KeyVault/vaults"]
_LOG_CATEGORIES = ["AuditEvent"]


class KeyVaultCollector(Collector):
    name = "key_vault"
    priority = 1
    description = "Key Vault audit events from Storage diagnostics."
    required_actions = (
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_diagnostic_logs(
            self, resource_types=_RESOURCE_TYPES, log_categories=_LOG_CATEGORIES
        )
