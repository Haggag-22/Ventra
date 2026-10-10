"""Azure Activity Log source — Monitor API or a subscription diagnostic storage archive.

Configured in ``acquisition.yaml`` as ``azure_log_backend`` and chosen in the Acquire UI.
Storage mode discovers the account from the subscription diagnostic setting. Ventra does
not create that setting or the storage account.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ACTIVITY_LOG_COLLECTOR = "activity_log"

# Categories a subscription diagnostic setting can export for the Activity Log.
ACTIVITY_LOG_STORAGE_CATEGORIES: tuple[str, ...] = (
    "Administrative",
    "Security",
    "ServiceHealth",
    "Alert",
    "Recommendation",
    "Policy",
    "Autoscale",
    "ResourceHealth",
)

_STORAGE_IAM: frozenset[str] = frozenset(
    {
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    }
)


@dataclass
class AzureLogBackendSpec:
    mode: str = "monitor_api"

    def uses_monitor_api(self) -> bool:
        return self.mode == "monitor_api"

    def uses_storage(self) -> bool:
        return self.mode == "storage"

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode}

    @classmethod
    def from_dict(cls, raw: Any) -> AzureLogBackendSpec:
        if not raw or not isinstance(raw, dict):
            return cls()
        mode = str(raw.get("mode") or "monitor_api").strip().lower()
        if mode not in ("monitor_api", "storage"):
            mode = "monitor_api"
        return cls(mode=mode)


def cart_needs_azure_log_backend(collector_names: list[str]) -> bool:
    return ACTIVITY_LOG_COLLECTOR in collector_names


def validate_azure_log_backend_dict(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("azure_log_backend must be an object.")
    mode = str(raw.get("mode") or "").strip().lower()
    if mode not in ("monitor_api", "storage"):
        raise ValueError(f"Unknown azure_log_backend mode: {raw.get('mode')!r}")
    return AzureLogBackendSpec(mode=mode).to_dict()


def apply_azure_log_backend_iam(wanted: set[str], raw: Any) -> set[str]:
    spec = AzureLogBackendSpec.from_dict(raw)
    if not spec.uses_storage():
        return wanted
    return set(wanted) | set(_STORAGE_IAM)
