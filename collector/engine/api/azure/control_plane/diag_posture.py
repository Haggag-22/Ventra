"""Azure diagnostic-settings posture collector.

For each IR cheat-sheet log source backed by diagnostic settings, discovers in-scope resources
and records where logs route (Storage / Log Analytics / Event Hub). Gaps are named by catalog
source id so the Logs Coverage panel shows real per-source status instead of "unknown".
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled

MAX_RESOURCES = 200

# Catalog source id → ARM resource type(s) checked for diagnostic routing.
POSTURE_CHECKS: dict[str, list[str]] = {
    "azure_firewall": ["Microsoft.Network/azureFirewalls"],
    "app_gateway": ["Microsoft.Network/applicationGateways"],
    "front_door": ["Microsoft.Network/frontDoors", "Microsoft.Cdn/profiles"],
    "dns": [
        "Microsoft.Network/dnsZones",
        "Microsoft.Network/privateDnsZones",
        "Microsoft.Network/dnsResolverEndpoints",
    ],
    "storage_access": ["Microsoft.Storage/storageAccounts"],
    "key_vault": ["Microsoft.KeyVault/vaults"],
    "aks_audit": ["Microsoft.ContainerService/managedClusters"],
}


def _classify_settings(settings: list[dict[str, Any]]) -> str:
    if not settings:
        return "none"
    has_storage = any(s.get("storage_account_id") for s in settings)
    has_la = any(s.get("workspace_id") for s in settings)
    has_eh = any(s.get("event_hub") for s in settings)
    if has_storage:
        return "storage"
    if has_la:
        return "log_analytics"
    if has_eh:
        return "event_hub"
    return "none"


class DiagPostureCollector(Collector):
    name = "diag_posture"
    priority = 2
    description = (
        "Diagnostic-settings posture for Storage-routed log sources: firewall, App Gateway, "
        "Front Door, DNS, storage, Key Vault, AKS audit."
    )
    required_actions = (
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Resources/subscriptions/resources/read",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        posture: dict[str, Any] = {}

        for source_id, resource_types in POSTURE_CHECKS.items():
            try:
                result = self._check_source(cf, resource_types)
            except Exception as exc:  # noqa: BLE001
                result = {"error": str(exc)}
                gaps.append((source_id, GapReason.COLLECTOR_ERROR, f"Posture check failed: {exc}"))
                posture[source_id] = result
                continue
            gap = result.pop("_gap", None)
            posture[source_id] = result
            if gap:
                gaps.append((source_id, gap[0], gap[1]))

        files = [self.write_json(posture, "config.json")]
        self.write_meta({"source": self.name, "checks": len(POSTURE_CHECKS)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=0,
            gaps=gaps,
            notes=f"Diagnostic posture recorded for {len(POSTURE_CHECKS)} source(s).",
        )

    def _check_source(self, cf, resource_types: list[str]) -> dict[str, Any]:
        total = 0
        storage = 0
        la_only = 0
        eh_only = 0
        none = 0
        sample: list[str] = []

        for sub in self.ctx.subscription_ids:
            try:
                resources = cf.resources_of_type(sub, resource_types)
            except AzureAccessDenied:
                raise
            except AzureServiceNotEnabled:
                continue
            for res in resources[:MAX_RESOURCES]:
                total += 1
                try:
                    settings = cf.diagnostic_settings(res["id"])
                except AzureAccessDenied:
                    settings = []
                except AzureServiceNotEnabled:
                    settings = []
                route = _classify_settings(settings)
                if route == "storage":
                    storage += 1
                elif route == "log_analytics":
                    la_only += 1
                elif route == "event_hub":
                    eh_only += 1
                else:
                    none += 1
                if len(sample) < 10:
                    sample.append(f"{res['name']}:{route}")

        out = {
            "resources_total": total,
            "routed_to_storage": storage,
            "log_analytics_only": la_only,
            "event_hub_only": eh_only,
            "no_routing": none,
            "sample": sample,
        }
        if total == 0:
            out["_gap"] = (GapReason.NOT_PRESENT, f"No {resource_types[0]} resources in scope.")
        elif none == total:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"No diagnostic settings on any of {total} resource(s).",
            )
        elif la_only and not storage:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"{la_only}/{total} resource(s) route logs to Log Analytics only — "
                "not collectible via Storage.",
            )
        elif eh_only and not storage:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"{eh_only}/{total} resource(s) route logs to Event Hub only — "
                "not collectible via Storage.",
            )
        elif none > 0 or la_only > 0 or eh_only > 0:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"{storage}/{total} resource(s) route to Storage; "
                f"{none} unrouted, {la_only} LA-only, {eh_only} EH-only.",
            )
        return out
