"""Node-plane collection across Kubernetes distributions.

The node-plane collectors were written against kubeadm, where the control plane runs as
static pods with per-component log trees. These tests pin the behaviour on the layouts that
do not look like that at all - k3s (one merged process, no manifests), RKE2, microk8s and a
managed worker with no local control plane - while the kubeadm tests in
``test_kubernetes_collectors.py`` guard against regressing the original path.

Every node is a temporary directory laid out like a host root. No cluster, journal, or
crictl is required: external commands come from a lookup table.
"""

from __future__ import annotations

import json
from pathlib import Path

from collector.clouds.kubernetes.node import NodeAccess
from collector.engine.api.kubernetes.api_plane.audit_posture import AuditPostureCollector
from collector.engine.api.kubernetes.common.distro import detect_distro
from collector.engine.api.kubernetes.node_plane.apiserver_audit import ApiserverAuditCollector
from collector.engine.api.kubernetes.node_plane.etcd import EtcdCollector
from collector.engine.api.kubernetes.node_plane.kubelet_logs import KubeletLogsCollector
from collector.engine.api.kubernetes.node_plane.runtime_logs import RuntimeLogsCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow


# --------------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------------
class FakeFactory:
    def __init__(self, node):
        self.node = node

    def __getattr__(self, name):
        if name.startswith("list_"):
            return lambda: []
        raise AttributeError(name)


def _ctx(tmp_path: Path, node, *, params=None) -> CollectionContext:
    staging = tmp_path / "staging"
    (staging / "sources").mkdir(parents=True, exist_ok=True)
    return CollectionContext(
        cloud="kubernetes",
        account_id="on-prem-cluster",
        regions=[],
        time_window=TimeWindow(),
        staging=staging,
        case_id="CASE-K8S-DISTRO",
        client_factory=FakeFactory(node),
        artifact_parameters=params or {},
    )


def _node(tmp_path: Path, files: dict[str, str], *, journals=None, name="node") -> NodeAccess:
    """A node root with ``files`` written, and journalctl answering from ``journals``."""
    root = tmp_path / name
    for host_path, content in files.items():
        p = root / host_path.lstrip("/")
        if host_path.endswith("/"):
            p.mkdir(parents=True, exist_ok=True)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    root.mkdir(parents=True, exist_ok=True)

    node = NodeAccess(root=root)
    table = dict(journals or {})

    def have(binary):
        return binary in {"journalctl"} | {a.split()[0] for a in table}

    def run(args, timeout=None):
        joined = " ".join(args)
        for key, value in table.items():
            if key in joined:
                return value
        return -1, "", f"{args[0]}: no such unit"

    node.have = have
    node.run = run
    return node


def _journal(unit: str, *messages: str) -> tuple[int, str, str]:
    lines = [
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": str(1781000000000000 + i),
                "_SYSTEMD_UNIT": f"{unit}.service",
                "PRIORITY": "6",
                "MESSAGE": msg,
            }
        )
        for i, msg in enumerate(messages)
    ]
    return 0, "\n".join(lines) + "\n", ""


# A default k3s server, matching what a live node looks like: no /etc/kubernetes at all,
# workload pods only under /var/log/pods, audit log on disk, sqlite datastore.
K3S_SERVER_FILES = {
    "/etc/rancher/k3s/config.yaml": (
        "write-kubeconfig-mode: '0644'\n"
        "kube-apiserver-arg:\n"
        "  - audit-log-path=/var/log/kubernetes/audit/audit.log\n"
        "  - audit-policy-file=/etc/rancher/k3s/audit-policy.yaml\n"
    ),
    "/etc/systemd/system/k3s.service": (
        "[Service]\nExecStart=/usr/local/bin/k3s server --write-kubeconfig-mode 644\n"
    ),
    "/var/lib/rancher/k3s/server/db/state.db": "sqlite-bytes",
    "/var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist": "{}",
    "/var/log/pods/kube-system_traefik-abc_uid1/traefik/0.log": "traefik up\n",
    "/var/log/kubernetes/audit/audit.log": json.dumps(
        {
            "kind": "Event",
            "stage": "ResponseComplete",
            "verb": "create",
            "user": {"username": "mallory"},
            "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod"},
            "requestReceivedTimestamp": "2026-06-11T10:00:00Z",
        }
    )
    + "\n",
    "/run/k3s/containerd/containerd.sock": "",
}


# --------------------------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------------------------
def test_detects_each_distribution(tmp_path: Path) -> None:
    cases = {
        "k3s": (K3S_SERVER_FILES, "k3s", "server", True),
        "rke2": (
            {
                "/etc/rancher/rke2/config.yaml": "profile: cis\n",
                "/var/lib/rancher/rke2/server/": "",
                "/etc/systemd/system/rke2-server.service": "[Service]\n",
            },
            "rke2",
            "server",
            True,
        ),
        "microk8s": (
            {"/var/snap/microk8s/current/args/kube-apiserver": "--audit-log-path=/x.log\n"},
            "microk8s",
            "control-plane",
            True,
        ),
        "kubeadm": (
            {"/etc/kubernetes/manifests/kube-apiserver.yaml": "spec: {}\n"},
            "kubeadm",
            "control-plane",
            False,
        ),
        "managed-worker": ({"/var/log/pods/": ""}, "unknown", "worker", False),
    }
    for label, (files, family, role, merged) in cases.items():
        info = detect_distro(_node(tmp_path, files, name=f"n-{label}"))
        assert info.family == family, label
        assert info.role == role, label
        assert info.merged_control_plane is merged, label
        assert info.signals or family == "unknown", label


def test_detection_is_cached_per_node(tmp_path: Path) -> None:
    node = _node(tmp_path, K3S_SERVER_FILES)
    first = detect_distro(node)
    assert detect_distro(node) is first  # resolved once per run, shared by all collectors


# --------------------------------------------------------------------------------------------
# k3s: control plane is one merged journal
# --------------------------------------------------------------------------------------------
def test_k3s_audit_log_is_collected_without_any_manifest(tmp_path: Path) -> None:
    """The live-verified case: audit file on disk, no /etc/kubernetes anywhere."""
    node = _node(tmp_path, K3S_SERVER_FILES)
    result = ApiserverAuditCollector(_ctx(tmp_path, node)).collect()
    assert result.record_count == 1
    assert result.status == SourceStatus.COLLECTED

    config = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_apiserver_audit" / "config.json").read_text()
    )
    assert config["distro"]["family"] == "k3s"
    assert config["audit_path"] == "/var/log/kubernetes/audit/audit.log"
    # Resolved from the k3s config, not from a kubeadm manifest.
    assert "/etc/rancher/k3s/config.yaml" in config["audit_path_source"]

    detections = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_apiserver_audit" / "detections.json").read_text()
    )
    assert len(detections["exec_or_attach"]) == 1


def test_k3s_audit_posture_reads_flags_from_distro_config(tmp_path: Path) -> None:
    files = dict(K3S_SERVER_FILES)
    files["/etc/rancher/k3s/audit-policy.yaml"] = (
        "rules:\n- level: RequestResponse\n  resources:\n  - group: ''\n"
        "    resources: ['secrets','pods/exec']\n"
    )
    node = _node(tmp_path, files)
    result = AuditPostureCollector(_ctx(tmp_path, node)).collect()
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_audit_posture" / "config.json").read_text())
    assert config["audit_enabled"] is True
    assert config["distro"]["family"] == "k3s"
    assert config["flags"]["audit-log-path"] == "/var/log/kubernetes/audit/audit.log"
    assert not any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)


def test_audit_posture_uses_the_log_on_disk_when_no_flag_source_exists(tmp_path: Path) -> None:
    """A node with the audit file but no readable flags is auditing, not un-audited."""
    node = _node(
        tmp_path,
        {"/var/log/kubernetes/audit/audit.log": "{}\n", "/var/log/pods/": ""},
    )
    result = AuditPostureCollector(_ctx(tmp_path, node)).collect()
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_audit_posture" / "config.json").read_text())
    assert config["audit_enabled"] is True
    assert config["audit_log_on_disk"] == "/var/log/kubernetes/audit/audit.log"
    # Not the critical "disabled" finding; the honest one is that the policy is unknown.
    assert not any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)
    assert any("policy could not be read" in g[2] for g in result.gaps)


def test_audit_posture_undetermined_is_not_reported_as_disabled(tmp_path: Path) -> None:
    node = _node(tmp_path, {"/var/log/pods/": ""})
    result = AuditPostureCollector(_ctx(tmp_path, node)).collect()
    assert result.status == SourceStatus.EMPTY
    assert result.gaps[0][1] == GapReason.NOT_PRESENT
    assert "UNDETERMINED" in result.gaps[0][2]
    assert "Looked at:" in result.gaps[0][2]


# --------------------------------------------------------------------------------------------
# k3s: datastore, kubelet and runtime
# --------------------------------------------------------------------------------------------
def test_k3s_sqlite_datastore_is_reported_with_the_right_controls(tmp_path: Path) -> None:
    node = _node(tmp_path, K3S_SERVER_FILES)
    result = EtcdCollector(_ctx(tmp_path, node)).collect()
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_etcd" / "config.json").read_text())
    datastore = config["datastore"]
    assert datastore["kind"] == "sqlite"
    assert datastore["path"] == "/var/lib/rancher/k3s/server/db/state.db"
    assert datastore["client_cert_auth_applicable"] is False
    # Plaintext Secrets in a sqlite file is the finding that matters here.
    assert any("plaintext" in issue for issue in datastore["issues"])
    # No etcd TLS directory on k3s sqlite, and that is stated rather than flagged missing.
    assert config["tls_material"]["present"] is False
    # The DB is never captured.
    assert not (tmp_path / "staging" / "sources" / "k8s_etcd" / "etcd-snapshot.db").exists()
    assert result.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)


def test_k3s_etcd_reads_the_merged_server_journal(tmp_path: Path) -> None:
    """With no separate etcd unit, datastore events come from journalctl -u k3s."""
    node = _node(
        tmp_path,
        K3S_SERVER_FILES,
        journals={"journalctl -u k3s": _journal("k3s", "etcd applied revision 42")},
    )
    result = EtcdCollector(_ctx(tmp_path, node)).collect()
    assert result.record_count == 1
    assert (tmp_path / "staging" / "sources" / "k8s_etcd" / "etcd.jsonl.gz").exists()
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_etcd" / "config.json").read_text())
    assert "journalctl -u k3s" in config["log_source"]
    assert "merged" in config["log_source"]


def test_k3s_kubelet_falls_back_to_the_agent_unit(tmp_path: Path) -> None:
    node = _node(
        tmp_path,
        K3S_SERVER_FILES,
        journals={"journalctl -u k3s": _journal("k3s", "Started kubelet", "SyncLoop ADD")},
    )
    result = KubeletLogsCollector(_ctx(tmp_path, node)).collect()
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_kubelet_logs" / "config.json").read_text())
    assert result.record_count == 2
    assert config["unit"] == "k3s"
    assert config["shared_unit"] is True
    assert "journalctl -u kubelet" in config["attempted"]
    assert "no unit of its own" in result.notes


def test_k3s_runtime_uses_embedded_socket_when_no_containerd_unit(tmp_path: Path) -> None:
    containers = {"containers": [{"id": "abc123", "labels": {}}]}
    seen: list[list[str]] = []
    node = _node(
        tmp_path,
        K3S_SERVER_FILES,
        # Keyed on the subcommand: the argv also carries --runtime-endpoint, because the k3s
        # socket is not where crictl looks by default.
        journals={
            "ps -a -o json": (0, json.dumps(containers), ""),
            "images -o json": (0, json.dumps({"images": []}), ""),
            "pods -o json": (0, json.dumps({"items": []}), ""),
            "inspect abc123": (0, json.dumps({"status": {"id": "abc123"}}), ""),
            "crictl version": (0, "RuntimeVersion: v1.7.11-k3s2\n", ""),
        },
    )
    inner_run = node.run
    node.run = lambda args, timeout=None: (seen.append(list(args)), inner_run(args, timeout))[1]

    result = RuntimeLogsCollector(_ctx(tmp_path, node)).collect()

    # crictl is pointed at the embedded socket through the host mount, so it works on a node
    # whose CRI socket is not at the default path.
    crictl_calls = [a for a in seen if a and a[0] == "crictl" and "--runtime-endpoint" in a]
    assert crictl_calls, "crictl should be called with an explicit endpoint"
    endpoint = crictl_calls[0][crictl_calls[0].index("--runtime-endpoint") + 1]
    assert endpoint.startswith("unix://")
    assert endpoint.endswith("/run/k3s/containerd/containerd.sock")
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_runtime_logs" / "config.json").read_text())
    assert config["runtime"]["runtime"] == "containerd"
    assert config["runtime"]["socket"] == "/run/k3s/containerd/containerd.sock"
    assert config["live_state_available"] is True
    assert config["containers_inspected"] == 1
    # The missing containerd unit is a partial result, not a failure.
    assert result.status == SourceStatus.PARTIAL
    assert any("live runtime state was captured" in g[2] for g in result.gaps)


# --------------------------------------------------------------------------------------------
# RKE2 and microk8s
# --------------------------------------------------------------------------------------------
def test_rke2_reads_audit_flags_from_its_pod_manifests(tmp_path: Path) -> None:
    node = _node(
        tmp_path,
        {
            "/etc/rancher/rke2/config.yaml": "profile: cis\n",
            "/var/lib/rancher/rke2/server/db/etcd/": "",
            "/etc/systemd/system/rke2-server.service": "[Service]\n",
            "/var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml": (
                "spec:\n  containers:\n  - command:\n    - kube-apiserver\n"
                "    - --audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log\n"
            ),
        },
        journals={"journalctl -u rke2-server": _journal("rke2-server", "Running kube-apiserver")},
    )
    # The audit path resolves out of the RKE2 pod manifest, not /etc/kubernetes.
    audit = ApiserverAuditCollector(_ctx(tmp_path, node)).collect()
    audit_config = json.loads(
        (tmp_path / "staging" / "sources" / "k8s_apiserver_audit" / "config.json").read_text()
    )
    assert audit_config["distro"]["family"] == "rke2"
    assert audit_config["audit_path"] == "/var/lib/rancher/rke2/server/logs/audit.log"
    assert audit.status == SourceStatus.EMPTY  # configured but the file is not on this node

    etcd = EtcdCollector(_ctx(tmp_path, node)).collect()
    etcd_config = json.loads((tmp_path / "staging" / "sources" / "k8s_etcd" / "config.json").read_text())
    assert etcd_config["distro"]["family"] == "rke2"
    assert etcd_config["datastore"]["kind"] == "etcd"
    assert etcd.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)


def test_microk8s_reads_flags_from_its_args_file(tmp_path: Path) -> None:
    node = _node(
        tmp_path,
        {
            "/var/snap/microk8s/current/args/kube-apiserver": (
                "--audit-log-path=/var/snap/microk8s/current/audit.log\n--audit-log-maxage=7\n"
            ),
            "/var/snap/microk8s/current/var/kubernetes/backend/": "",
        },
    )
    result = AuditPostureCollector(_ctx(tmp_path, node)).collect()
    config = json.loads((tmp_path / "staging" / "sources" / "k8s_audit_posture" / "config.json").read_text())
    assert config["distro"]["family"] == "microk8s"
    assert config["audit_enabled"] is True
    assert config["flags"]["audit-log-path"] == "/var/snap/microk8s/current/audit.log"
    assert any("maxage=7" in g[2] for g in result.gaps)  # short retention still surfaces

    etcd = EtcdCollector(_ctx(tmp_path, node)).collect()
    etcd_config = json.loads((tmp_path / "staging" / "sources" / "k8s_etcd" / "config.json").read_text())
    assert etcd_config["datastore"]["kind"] == "dqlite"
    assert etcd.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)


# --------------------------------------------------------------------------------------------
# Managed workers: gap cleanly, never crash
# --------------------------------------------------------------------------------------------
def test_managed_worker_gaps_cleanly_on_every_control_plane_collector(tmp_path: Path) -> None:
    """EKS/GKE/AKS worker: no local control plane at all. Nothing may raise."""
    node = _node(
        tmp_path,
        {
            "/var/log/pods/prod_web_uid1/web/0.log": "hello\n",
            "/run/containerd/containerd.sock": "",
        },
    )
    ctx = _ctx(tmp_path, node)

    etcd = EtcdCollector(ctx).collect()
    assert etcd.status == SourceStatus.EMPTY
    assert etcd.gaps[0][1] == GapReason.NOT_PRESENT

    audit = ApiserverAuditCollector(ctx).collect()
    assert audit.status == SourceStatus.EMPTY
    assert audit.gaps[0][1] == GapReason.LOGGING_NOT_CONFIGURED

    posture = AuditPostureCollector(ctx).collect()
    assert posture.status == SourceStatus.EMPTY

    kubelet = KubeletLogsCollector(ctx).collect()
    assert kubelet.status == SourceStatus.EMPTY
    assert "Tried:" in kubelet.gaps[0][2]
