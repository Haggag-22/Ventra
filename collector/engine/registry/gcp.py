"""GCP collector registry — loaded only for GCP acquisition and collection."""

from __future__ import annotations

from collector.lib.base import CollectorRegistry
from collector.engine.api.gcp.control_plane.cloud_audit_admin import CloudAuditAdminCollector
from collector.engine.api.gcp.control_plane.cloud_audit_data import CloudAuditDataCollector
from collector.engine.api.gcp.control_plane.cloud_audit_system import CloudAuditSystemCollector
from collector.engine.api.gcp.control_plane.logging_posture import LoggingPostureCollector
from collector.engine.api.gcp.detections.cloud_monitoring import CloudMonitoringCollector
from collector.engine.api.gcp.detections.scc_findings import SccFindingsCollector
from collector.engine.api.gcp.identity.iam_policy import IamPolicyCollector
from collector.engine.api.gcp.identity.login_events import LoginEventsCollector
from collector.engine.api.gcp.identity.project import ProjectCollector
from collector.engine.api.gcp.network.api_gateway import ApiGatewayCollector
from collector.engine.api.gcp.network.cloud_armor import CloudArmorCollector
from collector.engine.api.gcp.network.cloud_dns import CloudDnsCollector
from collector.engine.api.gcp.network.cloud_nat import CloudNatCollector
from collector.engine.api.gcp.network.firewall_logs import FirewallLogsCollector
from collector.engine.api.gcp.network.cloud_cdn import CloudCdnCollector
from collector.engine.api.gcp.network.load_balancer import LoadBalancerCollector
from collector.engine.api.gcp.network.network_posture import NetworkPostureCollector
from collector.engine.api.gcp.network.vpc_flow import VpcFlowCollector as GcpVpcFlowCollector
from collector.engine.api.gcp.workloads.cloud_functions import CloudFunctionsCollector
from collector.engine.api.gcp.workloads.gce import GceCollector
from collector.engine.api.gcp.workloads.gke_audit import GkeAuditCollector
from collector.engine.api.gcp.workloads.bigquery_audit import BigQueryAuditCollector
from collector.engine.api.gcp.workloads.cloud_sql import CloudSqlCollector
from collector.engine.api.gcp.workloads.secret_manager import SecretManagerCollector
from collector.engine.api.gcp.workloads.storage_access import StorageAccessCollector as GcpStorageAccessCollector
from collector.engine.api.gcp.workloads.vm_logs import VmLogsCollector

_COLLECTOR_CLASSES = (
    ProjectCollector,
    IamPolicyCollector,
    CloudAuditAdminCollector,
    CloudAuditSystemCollector,
    CloudAuditDataCollector,
    LoggingPostureCollector,
    LoginEventsCollector,
    GcpVpcFlowCollector,
    FirewallLogsCollector,
    CloudNatCollector,
    NetworkPostureCollector,
    LoadBalancerCollector,
    CloudCdnCollector,
    ApiGatewayCollector,
    CloudDnsCollector,
    CloudArmorCollector,
    VmLogsCollector,
    GceCollector,
    CloudFunctionsCollector,
    GkeAuditCollector,
    GcpStorageAccessCollector,
    BigQueryAuditCollector,
    CloudSqlCollector,
    SecretManagerCollector,
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
