"""Storage account blob access log collector (diagnostic settings → Storage)."""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import SourceResult
from ..common.diagnostics import collect_diagnostic_logs

_RESOURCE_TYPES = ["Microsoft.Storage/storageAccounts"]
_LOG_CATEGORIES = ["StorageRead", "StorageWrite", "StorageDelete"]


class StorageAccessCollector(Collector):
    name = "storage_access"
    priority = 1
    description = "Storage account read/write/delete access logs from Storage diagnostics."
    required_actions = (
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        return collect_diagnostic_logs(
            self,
            resource_types=_RESOURCE_TYPES,
            log_categories=_LOG_CATEGORIES,
            name_param="bucket_names",
            post_filter=True,
        )
