"""GCP collector registry — loaded only for GCP acquisition and collection."""

from __future__ import annotations

from collector.lib.base import CollectorRegistry
from collector.engine.api.gcp.control_plane.cloud_audit_admin import CloudAuditAdminCollector
from collector.engine.api.gcp.control_plane.cloud_audit_data import CloudAuditDataCollector
from collector.engine.api.gcp.control_plane.cloud_audit_system import CloudAuditSystemCollector
from collector.engine.api.gcp.detections.cloud_monitoring import CloudMonitoringCollector
from collector.engine.api.gcp.detections.scc_findings import SccFindingsCollector
from collector.engine.api.gcp.identity.iam_policy import IamPolicyCollector
from collector.engine.api.gcp.identity.login_events import LoginEventsCollector
from collector.engine.api.gcp.identity.project import ProjectCollector
from collector.engine.api.gcp.identity.workspace_audit import WorkspaceAuditCollector
from collector.engine.api.gcp.network.api_gateway import ApiGatewayCollector
from collector.engine.api.gcp.network.firewall_logs import FirewallLogsCollector
from collector.engine.api.gcp.network.load_balancer import LoadBalancerCollector
from collector.engine.api.gcp.network.vpc_flow import VpcFlowCollector as GcpVpcFlowCollector
from collector.engine.api.gcp.workloads.cloud_functions import CloudFunctionsCollector
from collector.engine.api.gcp.workloads.storage_access import StorageAccessCollector as GcpStorageAccessCollector
from collector.engine.api.gcp.workloads.vm_logs import VmLogsCollector

_COLLECTOR_CLASSES = (
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
