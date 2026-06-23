"""Azure collector registry — loaded only for Azure acquisition and collection."""

from __future__ import annotations

from collector.lib.base import CollectorRegistry
from collector.engine.api.azure.control_plane.activity_log import ActivityLogCollector
from collector.engine.api.azure.control_plane.diag_posture import DiagPostureCollector
from collector.engine.api.azure.control_plane.log_analytics import LogAnalyticsCollector
from collector.engine.api.azure.control_plane.resource_graph import ResourceGraphCollector
from collector.engine.api.azure.detections.defender import DefenderCollector
from collector.engine.api.azure.identity.entra_audit import EntraAuditCollector
from collector.engine.api.azure.identity.entra_directory import EntraDirectoryCollector
from collector.engine.api.azure.identity.entra_signin import EntraSignInCollector
from collector.engine.api.azure.identity.oauth_consent import OAuthConsentCollector
from collector.engine.api.azure.identity.rbac import RbacCollector
from collector.engine.api.azure.identity.subscription import SubscriptionCollector
from collector.engine.api.azure.m365.unified_audit import UnifiedAuditCollector
from collector.engine.api.azure.m365.unified_audit_search import UnifiedAuditSearchCollector
from collector.engine.api.azure.network.app_gateway import AppGatewayCollector
from collector.engine.api.azure.network.azure_firewall import AzureFirewallCollector
from collector.engine.api.azure.network.dns import DnsCollector
from collector.engine.api.azure.network.front_door import FrontDoorCollector
from collector.engine.api.azure.network.nsg_flow import NsgFlowCollector
from collector.engine.api.azure.network.vnet_flow import VNetFlowCollector
from collector.engine.api.azure.workloads.aks_audit import AksAuditCollector
from collector.engine.api.azure.workloads.key_vault import KeyVaultCollector
from collector.engine.api.azure.workloads.storage_access import StorageAccessCollector as AzureStorageAccessCollector

_COLLECTOR_CLASSES = (
    SubscriptionCollector,
    EntraSignInCollector,
    EntraAuditCollector,
    EntraDirectoryCollector,
    ActivityLogCollector,
    RbacCollector,
    UnifiedAuditCollector,
    UnifiedAuditSearchCollector,
    OAuthConsentCollector,
    DefenderCollector,
    VNetFlowCollector,
    NsgFlowCollector,
    AzureFirewallCollector,
    AppGatewayCollector,
    FrontDoorCollector,
    DnsCollector,
    AzureStorageAccessCollector,
    KeyVaultCollector,
    AksAuditCollector,
    ResourceGraphCollector,
    DiagPostureCollector,
    LogAnalyticsCollector,
)

_registry: CollectorRegistry | None = None
_order: list[str] | None = None


def get() -> tuple[CollectorRegistry, list[str]]:
    global _registry, _order
    if _registry is None:
        _registry = CollectorRegistry()
        _order = []
        for cls in _COLLECTOR_CLASSES:
            _registry.register(cls)
            _order.append(cls.name)
    return _registry, _order
