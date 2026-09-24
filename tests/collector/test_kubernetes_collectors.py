"""Unit tests for the on-prem Kubernetes collectors (API plane + node plane).

API-plane collectors run against a fake client factory; node-plane collectors run against a
real :class:`NodeAccess` pointed at a temporary directory laid out like a host root. No real
cluster, kubeconfig, crictl, or journalctl is required.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from collector.clouds.kubernetes.client_factory import KubeAccessDenied
from collector.clouds.kubernetes.node import NodeAccess
from collector.engine.api.kubernetes.api_plane.audit_posture import AuditPostureCollector
from collector.engine.api.kubernetes.api_plane.cluster_state import ClusterStateCollector
from collector.engine.api.kubernetes.api_plane.events import EventsCollector
from collector.engine.api.kubernetes.api_plane.rbac import RbacCollector
from collector.engine.api.kubernetes.node_plane.apiserver_audit import ApiserverAuditCollector
from collector.engine.api.kubernetes.node_plane.container_logs import ContainerLogsCollector
from collector.engine.api.kubernetes.node_plane.etcd import EtcdCollector
from collector.engine.api.kubernetes.node_plane.runtime_logs import RuntimeLogsCollector
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

    def cluster_version(self):
        val = self.responses.get("cluster_version", {"gitVersion": "v1.30.2", "platform": "linux/amd64"})
        if isinstance(val, Exception):
            raise val
        return dict(val)

    def api_resources(self):
        val = self.responses.get(
            "api_resources",
            {"group_versions": ["v1"], "groups": [], "resources": {"v1": []}, "errors": {}},
        )
        if isinstance(val, Exception):
            raise val
        return dict(val)


def _fake_node(root: Path, commands=None, binaries=()):
    """A NodeAccess whose external commands come from a table instead of the host.

    ``commands`` maps a substring of the joined argv to ``(rc, stdout, stderr)``; anything
    unmatched behaves like a missing binary. Node-plane collectors are exercised without a
    real crictl / journalctl / etcdctl anywhere on the machine.
    """
    node = NodeAccess(root=root)
    table = dict(commands or {})
    allowed = set(binaries) | {args.split()[0] for args in table}

    def have(binary):
        return binary in allowed

    def run(args, timeout=None):
        joined = " ".join(args)
        for key, value in table.items():
            if key in joined:
                return value
        return -1, "", f"{args[0]}: not available on node"

    node.have = have
    node.run = run
    return node


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
    window = TimeWindow(since=datetime(2020, 1, 1, tzinfo=UTC), until=datetime(2020, 1, 2, tzinfo=UTC))
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
    cf = FakeFactory(responses={"list_cluster_roles": cluster_roles, "list_cluster_role_bindings": crbs})
    assert RbacCollector(_ctx(tmp_path, cf)).collect().status in (
        SourceStatus.COLLECTED,
        SourceStatus.PARTIAL,
    )
    dangerous = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_rbac" / "dangerous_bindings.json").read_text()
    )
    anon = json.loads((tmp_path / "staging" / "sources" / "k8s_rbac" / "anonymous_bindings.json").read_text())
    assert any(d["binding"] == "ClusterRoleBinding/admin-binding" for d in dangerous)
    assert any(a["binding"] == "anon-binding" for a in anon)


def test_apiserver_audit_parses_and_detects(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "spec:\n  containers:\n  - command:\n    - kube-apiserver\n"
        "    - --audit-log-path=/var/log/kubernetes/audit/audit.log\n",
    )
    exec_event = {
        "kind": "Event",
        "stage": "ResponseComplete",
        "verb": "create",
        "user": {"username": "mallory"},
        "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod", "name": "web"},
        "requestReceivedTimestamp": "2026-06-11T10:00:00Z",
        "stageTimestamp": "2026-06-11T10:00:01Z",
    }
    secret_event = {
        "kind": "Event",
        "stage": "ResponseComplete",
        "verb": "get",
        "user": {"username": "mallory"},
        "objectRef": {"resource": "secrets", "namespace": "prod", "name": "db"},
        "stageTimestamp": "2026-06-11T10:00:02Z",
    }
    _write(
        root,
        "/var/log/kubernetes/audit/audit.log",
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


def test_events_merges_both_apis_and_dedupes_by_uid(tmp_path: Path) -> None:
    core = [
        {"metadata": {"uid": "u1"}, "reason": "OOMKilling"},
        {"metadata": {"uid": "u2"}, "reason": "Scheduled"},
    ]
    modern = [
        {"metadata": {"uid": "u2"}, "reason": "Scheduled"},  # same object, modern view
        {"metadata": {"uid": "u3"}, "reason": "FailedMount"},
    ]
    cf = FakeFactory(responses={"list_events": core, "list_events_v1": modern})
    result = EventsCollector(_ctx(tmp_path, cf)).collect()

    assert result.record_count == 3  # u1, u2 (once), u3
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_events" / "config.json").read_text())
    assert config["deduplicated"] == 1
    assert config["apis"]["core/v1"]["events"] == 2
    assert config["apis"]["events.k8s.io/v1"]["events"] == 2


def test_events_denied_on_one_api_still_collects_the_other(tmp_path: Path) -> None:
    cf = FakeFactory(
        responses={
            "list_events": KubeAccessDenied("list events", "forbidden"),
            "list_events_v1": [{"metadata": {"uid": "u9"}, "reason": "BackOff"}],
        }
    )
    result = EventsCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 1
    assert result.status == SourceStatus.PARTIAL
    assert any(g[1] == GapReason.ACCESS_DENIED and "core/v1" in g[2] for g in result.gaps)


# --------------------------------------------------------------------------------------------
# Pod logs — admission webhook targeting
# --------------------------------------------------------------------------------------------
def test_cluster_state_captures_environment_snapshot(tmp_path: Path) -> None:
    pods = [
        {
            "metadata": {"namespace": "prod", "name": "web"},
            "spec": {"containers": [{"name": "app", "image": "registry.k8s.io/pause:3.9"}]},
            "status": {"container_statuses": [{"name": "app", "image_id": "sha256:aaa"}]},
        },
        {
            "metadata": {"namespace": "prod", "name": "miner"},
            "spec": {"containers": [{"name": "c", "image": "docker.io/evil/xmrig:latest"}]},
            "status": {"container_statuses": [{"name": "c", "image_id": "sha256:bbb"}]},
        },
    ]
    namespaces = [
        {"metadata": {"name": "prod", "labels": {"pod-security.kubernetes.io/enforce": "baseline"}}},
        {"metadata": {"name": "loose", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}},
        {"metadata": {"name": "bare", "labels": {}}},
    ]
    pvs = [
        {"metadata": {"name": "pv-host"}, "spec": {"host_path": {"path": "/mnt/data"}}},
        {"metadata": {"name": "pv-nfs"}, "spec": {"nfs": {"path": "/exports"}}},
    ]
    cf = FakeFactory(
        responses={"list_pods": pods, "list_namespaces": namespaces, "list_persistent_volumes": pvs}
    )
    result = ClusterStateCollector(_ctx(tmp_path, cf)).collect()
    src = tmp_path / "staging" / "sources" / "k8s_cluster_state"

    images = json.loads((src / "images.json").read_text())
    assert {i["image"] for i in images["images"]} == {
        "registry.k8s.io/pause:3.9",
        "docker.io/evil/xmrig:latest",
    }
    assert [i["imageID"] for i in images["images"] if i["image"].endswith("pause:3.9")] == ["sha256:aaa"]
    assert [i["image"] for i in images["untrusted"]] == ["docker.io/evil/xmrig:latest"]

    env = json.loads((src / "environment.json").read_text())
    assert env["cluster"]["determined"] is True
    assert env["cluster"]["gitVersion"] == "v1.30.2"
    assert env["discovery"]["determined"] is True

    security = json.loads((src / "pod_security.json").read_text())
    assert security["privileged_namespaces"] == ["loose"]
    assert security["unlabelled_namespaces"] == ["bare"]

    hostpath = json.loads((src / "hostpath_volumes.json").read_text())
    assert [p["name"] for p in hostpath] == ["pv-host"]
    assert any("hostPath-backed" in g[2] for g in result.gaps)
    assert any("privileged' Pod Security" in g[2] for g in result.gaps)


def test_cluster_state_never_writes_secret_values(tmp_path: Path) -> None:
    # The factory's list_secrets_metadata is what strips payloads; the collector must not
    # reintroduce them, so assert on everything the collector actually wrote.
    secrets = [
        {
            "metadata": {"namespace": "prod", "name": "db", "uid": "s1"},
            "type": "Opaque",
        }
    ]
    cf = FakeFactory(responses={"list_secrets_metadata": secrets})
    ClusterStateCollector(_ctx(tmp_path, cf)).collect()

    src = tmp_path / "staging" / "sources" / "k8s_cluster_state"
    blob = b""
    for path in sorted(src.rglob("*")):
        if path.is_file():
            blob += path.read_bytes() if path.suffix != ".gz" else gzip.decompress(path.read_bytes())
    assert b'"data"' not in blob
    assert b"stringData" not in blob and b"string_data" not in blob
    assert b'"db"' in blob  # the metadata itself is present


# --------------------------------------------------------------------------------------------
# API-server audit — path fallbacks and webhook backends
# --------------------------------------------------------------------------------------------
def test_apiserver_audit_uses_default_path_fallback(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    # No apiserver manifest at all; the log sits at the documented fallback location.
    _write(
        root,
        "/var/log/kube-apiserver-audit.log",
        json.dumps({"kind": "Event", "verb": "get", "objectRef": {"resource": "secrets"}}) + "\n",
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = ApiserverAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 1
    config = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_apiserver_audit" / "config.json").read_text()
    )
    assert config["files"] == ["/var/log/kube-apiserver-audit.log"]


def test_apiserver_audit_reads_gzipped_rotated_siblings(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "    - --audit-log-path=/var/log/kubernetes/audit/audit.log\n",
    )
    _write(
        root,
        "/var/log/kubernetes/audit/audit.log",
        json.dumps({"kind": "Event", "verb": "create", "objectRef": {"resource": "pods"}}) + "\n",
    )
    rotated = root / "var/log/kubernetes/audit/audit-2026-09-01T00-00-00.123.log.gz"
    rotated.write_bytes(
        gzip.compress(
            (
                json.dumps(
                    {
                        "kind": "Event",
                        "verb": "create",
                        "objectRef": {"resource": "pods", "subresource": "exec"},
                    }
                )
                + "\n"
            ).encode()
        )
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = ApiserverAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 2
    dets = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_apiserver_audit" / "detections.json").read_text()
    )
    assert len(dets["exec_or_attach"]) == 1


def test_apiserver_audit_webhook_only_backend_is_not_present_not_disabled(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "    - --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml\n",
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = ApiserverAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.EMPTY
    assert result.gaps[0][1] == GapReason.NOT_PRESENT
    assert "webhook" in result.gaps[0][2].lower()
    assert "k8s_audit_posture" in result.gaps[0][2]


def test_audit_posture_webhook_only_is_enabled_but_gapped(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "    - --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml\n"
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
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_audit_posture" / "config.json").read_text())
    assert config["audit_enabled"] is True
    assert config["log_backend"] is False
    # Enabled, so NOT the critical "disabled" gap — but the file is off-node, which is a gap.
    assert not any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)
    assert any(g[1] == GapReason.NOT_PRESENT and "WEBHOOK" in g[2] for g in result.gaps)


def test_audit_posture_flags_short_retention(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "    - --audit-log-path=/var/log/kubernetes/audit/audit.log\n"
        "    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml\n"
        "    - --audit-log-maxage=2\n"
        "    - --audit-log-maxbackup=1\n",
    )
    _write(
        root,
        "/etc/kubernetes/audit-policy.yaml",
        "rules:\n- level: RequestResponse\n  resources:\n  - group: ''\n"
        "    resources: ['secrets','pods/exec']\n",
    )
    cf = FakeFactory(node=NodeAccess(root=root))
    result = AuditPostureCollector(_ctx(tmp_path, cf)).collect()
    joined = " ".join(g[2] for g in result.gaps)
    assert "--audit-log-maxage=2" in joined
    assert "--audit-log-maxbackup=1" in joined


# --------------------------------------------------------------------------------------------
# Control-plane logs — journal and crictl fallbacks
# --------------------------------------------------------------------------------------------
def test_etcd_inventories_pki_without_copying_private_keys(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/etcd.yaml",
        "    - --client-cert-auth=true\n"
        "    - --listen-client-urls=https://127.0.0.1:2379\n"
        "    - --cert-file=/etc/kubernetes/pki/etcd/server.crt\n"
        "    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt\n",
    )
    _write(root, "/etc/kubernetes/pki/etcd/server.crt", "-----BEGIN CERTIFICATE-----\n")
    _write(root, "/etc/kubernetes/pki/etcd/server.key", "-----BEGIN PRIVATE KEY-----\nSECRETKEY\n")
    cf = FakeFactory(node=NodeAccess(root=root))
    EtcdCollector(_ctx(tmp_path, cf)).collect()

    src = tmp_path / "staging" / "sources" / "k8s_etcd"
    config = json.loads((src / "config.json").read_text())
    by_path = {f["path"]: f for f in config["tls_material"]["files"]}
    key = by_path["/etc/kubernetes/pki/etcd/server.key"]
    crt = by_path["/etc/kubernetes/pki/etcd/server.crt"]
    assert key["captured"] is False and key["sha256"]
    assert crt["captured"] is True and crt["sha256"]
    assert not (src / "pki" / "server.key").exists()
    assert (src / "pki" / "server.crt").exists()
    # The key material itself never lands in the evidence tree.
    blob = b"".join(p.read_bytes() for p in src.rglob("*") if p.is_file())
    assert b"SECRETKEY" not in blob


def test_etcd_flags_missing_encryption_at_rest_and_reports_data_dir(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/etcd.yaml",
        "    - --client-cert-auth=true\n"
        "    - --listen-client-urls=https://127.0.0.1:2379\n"
        "    - --cert-file=/etc/kubernetes/pki/etcd/server.crt\n"
        "    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt\n",
    )
    # kube-apiserver present but with no --encryption-provider-config.
    _write(root, "/etc/kubernetes/manifests/kube-apiserver.yaml", "    - --advertise-address=10.0.0.1\n")
    _write(root, "/var/lib/etcd/member/snap/db", "x" * 64)
    cf = FakeFactory(node=NodeAccess(root=root))
    result = EtcdCollector(_ctx(tmp_path, cf)).collect()

    assert any("encryption-at-rest is NOT configured" in g[2] for g in result.gaps)
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_etcd" / "config.json").read_text())
    assert config["data_dir"]["present"] is True
    assert config["data_dir"]["total_bytes"] == 64
    # The DB itself is never captured.
    assert not (tmp_path / "staging" / "sources" / "k8s_etcd" / "etcd-snapshot.db").exists()


def test_etcd_collects_topology_and_flags_unhealthy_endpoint(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(
        root,
        "/etc/kubernetes/manifests/etcd.yaml",
        "    - --client-cert-auth=true\n"
        "    - --listen-client-urls=https://127.0.0.1:2379\n"
        "    - --cert-file=/etc/kubernetes/pki/etcd/server.crt\n"
        "    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt\n",
    )
    node = _fake_node(
        root,
        commands={
            "etcdctl member list": (0, json.dumps({"members": [{"name": "cp1"}, {"name": "cp2"}]}), ""),
            "etcdctl endpoint health": (
                0,
                json.dumps(
                    [
                        {"endpoint": "https://127.0.0.1:2379", "health": True},
                        {"endpoint": "https://10.0.0.9:2379", "health": False},
                    ]
                ),
                "",
            ),
        },
    )
    cf = FakeFactory(node=node)
    result = EtcdCollector(_ctx(tmp_path, cf)).collect()
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_etcd" / "config.json").read_text())
    assert config["topology"]["member_count"] == 2
    assert config["topology"]["unhealthy_endpoints"] == ["https://10.0.0.9:2379"]
    assert any("unhealthy" in g[2] for g in result.gaps)


# --------------------------------------------------------------------------------------------
# Runtime logs / container logs
# --------------------------------------------------------------------------------------------
def test_runtime_logs_inspects_each_container(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    (root / "var/lib/containerd").mkdir(parents=True)
    containers = {
        "containers": [
            {
                "id": "cid1",
                "labels": {
                    "io.kubernetes.pod.name": "web",
                    "io.kubernetes.pod.namespace": "prod",
                    "io.kubernetes.container.name": "app",
                },
            }
        ]
    }
    node = _fake_node(
        root,
        commands={
            "crictl ps -a -o json": (0, json.dumps(containers), ""),
            "crictl images": (0, json.dumps({"images": []}), ""),
            "crictl pods": (0, json.dumps({"items": []}), ""),
            "crictl inspect cid1": (0, json.dumps({"status": {"id": "cid1"}}), ""),
            "crictl version": (0, "RuntimeVersion: v1.7.0\n", ""),
        },
    )
    cf = FakeFactory(node=node)
    result = RuntimeLogsCollector(_ctx(tmp_path, cf)).collect()

    src = tmp_path / "staging" / "sources" / "k8s_runtime_logs"
    config = json.loads((src / "config.json").read_text())
    assert config["containers_inspected"] == 1
    rows = [
        json.loads(line)
        for line in gzip.decompress((src / "container_inspect.jsonl.gz").read_bytes()).decode().splitlines()
    ]
    assert rows[0]["container_id"] == "cid1"
    assert rows[0]["namespace"] == "prod"
    assert rows[0]["inspect"]["status"]["id"] == "cid1"
    assert rows[0]["_ventra_runtime"] == "containerd"  # NodeContext stamped
    assert result.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)


def test_container_logs_collects_rotated_siblings(tmp_path: Path) -> None:
    root = _node_root(tmp_path)
    _write(root, "/var/log/pods/prod_web_uid123/app/0.log", "current\n")
    _write(root, "/var/log/pods/prod_web_uid123/app/0.log.20260101-120000", "rotated\n")
    cf = FakeFactory(node=NodeAccess(root=root))
    result = ContainerLogsCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 2
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_container_logs" / "config.json").read_text())
    assert config["rotated_logs"] == 1
    assert {e["namespace"] for e in config["logs"]} == {"prod"}


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
