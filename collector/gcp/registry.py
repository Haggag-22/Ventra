"""GCP collector registry — all sources in stable registration order."""

from __future__ import annotations

from ..lib.base import CollectorRegistry
from .control_plane.cloud_audit_admin import CloudAuditAdminCollector
from .control_plane.cloud_audit_data import CloudAuditDataCollector
from .control_plane.cloud_audit_system import CloudAuditSystemCollector
from .detections.cloud_monitoring import CloudMonitoringCollector
from .detections.scc_findings import SccFindingsCollector
from .identity.iam_policy import IamPolicyCollector
from .identity.login_events import LoginEventsCollector
from .identity.project import ProjectCollector
from .identity.workspace_audit import WorkspaceAuditCollector
from .network.api_gateway import ApiGatewayCollector
from .network.firewall_logs import FirewallLogsCollector
from .network.load_balancer import LoadBalancerCollector
from .network.vpc_flow import VpcFlowCollector
from .workloads.cloud_functions import CloudFunctionsCollector
from .workloads.storage_access import StorageAccessCollector
from .workloads.vm_logs import VmLogsCollector

GCP_REGISTRY = CollectorRegistry()

COLLECTOR_ORDER: list[str] = []

for _cls in (
    ProjectCollector,
    IamPolicyCollector,
    CloudAuditAdminCollector,
    CloudAuditSystemCollector,
    CloudAuditDataCollector,
    LoginEventsCollector,
    WorkspaceAuditCollector,
    VpcFlowCollector,
    FirewallLogsCollector,
    LoadBalancerCollector,
    ApiGatewayCollector,
    VmLogsCollector,
    CloudFunctionsCollector,
    StorageAccessCollector,
    SccFindingsCollector,
    CloudMonitoringCollector,
):
    GCP_REGISTRY.register(_cls)
    COLLECTOR_ORDER.append(_cls.name)


def all_collector_names() -> list[str]:
    return list(COLLECTOR_ORDER)
