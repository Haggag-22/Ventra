"""Azure collector registry — all 22 sources in stable registration order."""

from __future__ import annotations

from ..lib.base import CollectorRegistry
from .control_plane.activity_log import ActivityLogCollector
from .control_plane.diag_posture import DiagPostureCollector
from .control_plane.log_analytics import LogAnalyticsCollector
from .control_plane.resource_graph import ResourceGraphCollector
from .detections.defender import DefenderCollector
from .identity.entra_audit import EntraAuditCollector
from .identity.entra_directory import EntraDirectoryCollector
from .identity.entra_signin import EntraSignInCollector
from .identity.oauth_consent import OAuthConsentCollector
from .identity.rbac import RbacCollector
from .identity.subscription import SubscriptionCollector
from .m365.unified_audit import UnifiedAuditCollector
from .m365.unified_audit_search import UnifiedAuditSearchCollector
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
    SubscriptionCollector,  # Account Context
    EntraSignInCollector,  # Entra ID Sign-ins Logs
    EntraAuditCollector,  # Entra ID Audit Logs
    EntraDirectoryCollector,  # Entra ID Directory Objects -> IAM Snapshot
    ActivityLogCollector,  # Activity Log -> CloudTrail Timeline
    RbacCollector,  # RBAC -> IAM Snapshot

    # M365 CRITICAL
    UnifiedAuditCollector,  # M365 Unified Audit Log (Management API, ~7d)
    UnifiedAuditSearchCollector,  # M365 UAL Search-UnifiedAuditLog (90d default)
    OAuthConsentCollector,  # OAuth2 consent grants

    # Findings
    DefenderCollector,  # Defender for Cloud alerts
    
    # Network flow + edge
    VNetFlowCollector, # VNet Flow Logs
    NsgFlowCollector, # NSG Flow Logs       
    AzureFirewallCollector,
    AppGatewayCollector, # Application Gateway / WAF
    FrontDoorCollector, # Front Door access / WAF
    DnsCollector, # DNS

    # Data access + Kubernetes audit
    StorageAccessCollector,
    KeyVaultCollector,
    AksAuditCollector,

    # Inventory + posture
    ResourceGraphCollector,
    DiagPostureCollector,
    LogAnalyticsCollector,
):
    AZURE_REGISTRY.register(_cls)
    COLLECTOR_ORDER.append(_cls.name)


def all_collector_names() -> list[str]:
    """Every registered Azure collector, in stable registration order."""
    return list(COLLECTOR_ORDER)
