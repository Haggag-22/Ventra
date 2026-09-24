"""Kubernetes (on-prem) collector registry — loaded only for kubernetes collection.

Registration order is the run order, and it enforces the volatility ordering from the build
spec: Events first (gone in ~1h), then ephemeral container evidence, then node logs, then
the durable API-server audit log and cluster object specs.
"""

from __future__ import annotations

from collector.engine.api.kubernetes.api_plane.audit_posture import AuditPostureCollector
from collector.engine.api.kubernetes.api_plane.cluster_state import ClusterStateCollector
from collector.engine.api.kubernetes.api_plane.events import EventsCollector
from collector.engine.api.kubernetes.api_plane.rbac import RbacCollector
from collector.engine.api.kubernetes.node_plane.apiserver_audit import ApiserverAuditCollector
from collector.engine.api.kubernetes.node_plane.cni_logs import CniLogsCollector
from collector.engine.api.kubernetes.node_plane.container_logs import ContainerLogsCollector
from collector.engine.api.kubernetes.node_plane.etcd import EtcdCollector
from collector.engine.api.kubernetes.node_plane.kubelet_logs import KubeletLogsCollector
from collector.engine.api.kubernetes.node_plane.runtime_logs import RuntimeLogsCollector
from collector.lib.base import CollectorRegistry

_COLLECTOR_CLASSES = (
    # 1. Most perishable — Events are garbage-collected after ~1h by default.
    EventsCollector,
    # 2. Ephemeral container logs on the node filesystem.
    ContainerLogsCollector,
    # 3. Runtime + node / datastore logs.
    RuntimeLogsCollector,
    KubeletLogsCollector,
    EtcdCollector,
    CniLogsCollector,
    # 4. Durable: API-server audit log on disk, then cluster object specs.
    ApiserverAuditCollector,
    AuditPostureCollector,
    ClusterStateCollector,
    RbacCollector,
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
