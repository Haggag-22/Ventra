"""Map artifact collector keys to engine API modules and collector classes."""

from __future__ import annotations

from ..lib.base import CollectorRegistry
from .api.aws.control_plane.cloudtrail import CloudTrailCollector
from .api.aws.control_plane.config import ConfigCollector
from .api.aws.control_plane.log_posture import LogPostureCollector
from .api.aws.detections.detective import DetectiveCollector
from .api.aws.detections.guardduty import GuardDutyCollector
from .api.aws.detections.inspector2 import Inspector2Collector
from .api.aws.detections.macie import MacieCollector
from .api.aws.detections.securityhub import SecurityHubCollector
from .api.aws.identity.account import AccountCollector
from .api.aws.identity.iam import IamCollector
from .api.aws.identity.kms import KmsCollector
from .api.aws.identity.secrets import SecretsCollector
from .api.aws.network.cloudfront import CloudFrontCollector
from .api.aws.network.elb_alb import ElbAlbCollector
from .api.aws.network.route53_resolver import Route53ResolverCollector
from .api.aws.network.vpc_flow import VpcFlowCollector
from .api.aws.network.waf import WafCollector
from .api.aws.workloads.ec2 import Ec2Collector
from .api.aws.workloads.eks_audit import EksAuditCollector
from .api.aws.workloads.lambda_ import LambdaCollector
from .api.aws.workloads.s3 import S3Collector
from .api.aws.workloads.s3_access import S3AccessCollector
from .api.azure.control_plane.activity_log import ActivityLogCollector
from .api.azure.control_plane.diag_posture import DiagPostureCollector
from .api.azure.control_plane.log_analytics import LogAnalyticsCollector
from .api.azure.control_plane.resource_graph import ResourceGraphCollector
from .api.azure.detections.defender import DefenderCollector
from .api.azure.identity.entra_audit import EntraAuditCollector
from .api.azure.identity.entra_directory import EntraDirectoryCollector
from .api.azure.identity.entra_signin import EntraSignInCollector
from .api.azure.identity.oauth_consent import OAuthConsentCollector
from .api.azure.identity.rbac import RbacCollector
from .api.azure.identity.subscription import SubscriptionCollector
from .api.azure.m365.unified_audit import UnifiedAuditCollector
from .api.azure.m365.unified_audit_search import UnifiedAuditSearchCollector
from .api.azure.network.app_gateway import AppGatewayCollector
from .api.azure.network.azure_firewall import AzureFirewallCollector
from .api.azure.network.dns import DnsCollector
from .api.azure.network.front_door import FrontDoorCollector
from .api.azure.network.nsg_flow import NsgFlowCollector
from .api.azure.network.vnet_flow import VNetFlowCollector
from .api.azure.workloads.aks_audit import AksAuditCollector
from .api.azure.workloads.key_vault import KeyVaultCollector
from .api.azure.workloads.storage_access import StorageAccessCollector as AzureStorageAccessCollector
from .api.gcp.control_plane.cloud_audit_admin import CloudAuditAdminCollector
from .api.gcp.control_plane.cloud_audit_data import CloudAuditDataCollector
from .api.gcp.control_plane.cloud_audit_system import CloudAuditSystemCollector
from .api.gcp.detections.cloud_monitoring import CloudMonitoringCollector
from .api.gcp.detections.scc_findings import SccFindingsCollector
from .api.gcp.identity.iam_policy import IamPolicyCollector
from .api.gcp.identity.login_events import LoginEventsCollector
from .api.gcp.identity.project import ProjectCollector
from .api.gcp.identity.workspace_audit import WorkspaceAuditCollector
from .api.gcp.network.api_gateway import ApiGatewayCollector
from .api.gcp.network.firewall_logs import FirewallLogsCollector
from .api.gcp.network.load_balancer import LoadBalancerCollector
from .api.gcp.network.vpc_flow import VpcFlowCollector as GcpVpcFlowCollector
from .api.gcp.workloads.cloud_functions import CloudFunctionsCollector
from .api.gcp.workloads.storage_access import StorageAccessCollector as GcpStorageAccessCollector
from .api.gcp.workloads.vm_logs import VmLogsCollector

AWS_REGISTRY = CollectorRegistry()
AZURE_REGISTRY = CollectorRegistry()
GCP_REGISTRY = CollectorRegistry()

AWS_COLLECTOR_ORDER: list[str] = []
AZURE_COLLECTOR_ORDER: list[str] = []
GCP_COLLECTOR_ORDER: list[str] = []

for _cls in (
    AccountCollector,
    CloudTrailCollector,
    IamCollector,
    VpcFlowCollector,
    WafCollector,
    GuardDutyCollector,
    MacieCollector,
    DetectiveCollector,
    ConfigCollector,
    SecurityHubCollector,
    Inspector2Collector,
    KmsCollector,
    SecretsCollector,
    Ec2Collector,
    S3Collector,
    LambdaCollector,
    ElbAlbCollector,
    CloudFrontCollector,
    S3AccessCollector,
    Route53ResolverCollector,
    EksAuditCollector,
    LogPostureCollector,
):
    AWS_REGISTRY.register(_cls)
    AWS_COLLECTOR_ORDER.append(_cls.name)

for _cls in (
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
):
    AZURE_REGISTRY.register(_cls)
    AZURE_COLLECTOR_ORDER.append(_cls.name)

for _cls in (
    ProjectCollector,
    IamPolicyCollector,
    CloudAuditAdminCollector,
    CloudAuditSystemCollector,
    CloudAuditDataCollector,
    LoginEventsCollector,
    WorkspaceAuditCollector,
    GcpVpcFlowCollector,
    FirewallLogsCollector,
    LoadBalancerCollector,
    ApiGatewayCollector,
    VmLogsCollector,
    CloudFunctionsCollector,
    GcpStorageAccessCollector,
    SccFindingsCollector,
    CloudMonitoringCollector,
):
    GCP_REGISTRY.register(_cls)
    GCP_COLLECTOR_ORDER.append(_cls.name)

# Artifact ``type`` or ``collector`` alias → dotted API module path (without collector class).
API_MODULE_BY_COLLECTOR: dict[str, str] = {}
for _cloud, _reg in (
    ("aws", AWS_REGISTRY),
    ("azure", AZURE_REGISTRY),
    ("gcp", GCP_REGISTRY),
):
    for _name, _cls in _reg.all().items():
        mod = _cls.__module__
        API_MODULE_BY_COLLECTOR[_name] = mod
        API_MODULE_BY_COLLECTOR[f"{_cloud}.{_name}"] = mod

AUTODETECT_COLLECTORS: dict[str, tuple[str, str]] = {}


def registry_for_cloud(cloud: str) -> CollectorRegistry:
    cloud = cloud.lower()
    if cloud == "aws":
        return AWS_REGISTRY
    if cloud == "azure":
        return AZURE_REGISTRY
    if cloud == "gcp":
        return GCP_REGISTRY
    raise ValueError(f"unsupported cloud: {cloud}")


def collector_class_for(collector_key: str):
    """Resolve a registry id or alias to a collector class."""
    key = collector_key.strip()
    for reg in (AWS_REGISTRY, AZURE_REGISTRY, GCP_REGISTRY):
        cls = reg.get(key)
        if cls is not None:
            return cls
    if "." in key:
        _, bare = key.split(".", 1)
        for reg in (AWS_REGISTRY, AZURE_REGISTRY, GCP_REGISTRY):
            cls = reg.get(bare)
            if cls is not None:
                return cls
    raise KeyError(f"unknown collector: {collector_key}")


def artifact_type_for_collector(collector_key: str) -> str:
    return API_MODULE_BY_COLLECTOR.get(collector_key, "")
