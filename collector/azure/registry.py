"""Azure collector registry — all 20 sources in stable registration order."""

from __future__ import annotations

from ..lib.base import CollectorRegistry
from .control_plane.activity_log import ActivityLogCollector
from .control_plane.diag_posture import DiagPostureCollector
from .control_plane.resource_graph import ResourceGraphCollector
from .detections.defender import DefenderCollector
from .identity.entra_audit import EntraAuditCollector
from .identity.entra_directory import EntraDirectoryCollector
from .identity.entra_signin import EntraSignInCollector
from .identity.oauth_consent import OAuthConsentCollector
from .identity.rbac import RbacCollector
from .identity.subscription import SubscriptionCollector
from .m365.unified_audit import UnifiedAuditCollector
from .network.app_gateway import AppGatewayCollector
from .network.azure_firewall import AzureFirewallCollector
from .network.dns import DnsCollector
from .network.front_door import FrontDoorCollector
from .network.nsg_flow import NsgFlowCollector
from .network.vnet_flow import VNetFlowCollector
from .workloads.aks_audit import AksAuditCollector
from .workloads.key_vault import KeyVaultCollector
from .workloads.storage_access import StorageAccessCollector

AZURE_REGISTRY = CollectorRegistry()

COLLECTOR_ORDER: list[str] = []

for _cls in (
    # Context + identity backbone
    SubscriptionCollector,
    EntraSignInCollector,
    EntraAuditCollector,
    EntraDirectoryCollector,
    ActivityLogCollector,
    RbacCollector,
    # M365 CRITICAL
    UnifiedAuditCollector,
    OAuthConsentCollector,
    # Findings
    DefenderCollector,
    # Network flow + edge
    VNetFlowCollector,
    NsgFlowCollector,
    AzureFirewallCollector,
    AppGatewayCollector,
    FrontDoorCollector,
    DnsCollector,
    # Data access + Kubernetes audit
    StorageAccessCollector,
    KeyVaultCollector,
    AksAuditCollector,
    # Inventory + posture
    ResourceGraphCollector,
    DiagPostureCollector,
):
    AZURE_REGISTRY.register(_cls)
    COLLECTOR_ORDER.append(_cls.name)


def all_collector_names() -> list[str]:
    """Every registered Azure collector, in stable registration order."""
    return list(COLLECTOR_ORDER)
