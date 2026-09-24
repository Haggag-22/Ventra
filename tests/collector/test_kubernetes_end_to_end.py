"""End-to-end on-prem Kubernetes collection against a fake API plane.

Proves the acceptance criteria through the real runner rather than one collector at a time:

  * an **API-plane-only** run (kubeconfig, no node access) completes for events, pod_logs,
    cluster_state, rbac and audit_posture, and seals a signed package;
  * a single denied verb produces a gap on that one source while every other source still
    collects — the run never aborts;
  * a missing audit log is a critical gap cross-linked to the posture collector;
  * Secret ``.data`` values never appear anywhere in the sealed evidence.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path

from collector.clouds.kubernetes.client_factory import KubeAccessDenied, KubeIdentity
from collector.clouds.kubernetes.node import NodeAccess
from collector.engine.api.kubernetes.runner import (
    KubernetesRunConfig,
    parse_window,
    run_kubernetes_collection,
)

API_PLANE_COLLECTORS = [
    "k8s_events",
    "k8s_cluster_state",
    "k8s_rbac",
    "k8s_audit_posture",
]


class FakeApiPlane:
    """A kubeconfig-only factory: every API read answers, the node plane is absent."""

    def __init__(self, *, denied: set[str] | None = None) -> None:
        # Points at a path that does not exist — exactly what an operator workstation looks
        # like to a node-plane collector.
        self.node = NodeAccess(root=Path("/nonexistent-node-root"))
        self._denied = denied or set()
        self._pods = [
            {
                "metadata": {"namespace": "prod", "name": "web", "uid": "p1"},
                "spec": {
                    "containers": [{"name": "app", "image": "registry.k8s.io/pause:3.9"}],
                    "volumes": [{"host_path": {"path": "/var/run/docker.sock"}}],
                },
                "status": {"container_statuses": [{"name": "app", "image_id": "sha256:aaa"}]},
            }
        ]

    def cluster_identity(self) -> KubeIdentity:
        return KubeIdentity(
            cluster_id="lab-cluster",
            server_url="https://10.0.0.1:6443",
            server_version="v1.30.2",
            username="ventra-collector",
        )

    def _guard(self, name: str) -> None:
        if name in self._denied:
            raise KubeAccessDenied(name, "forbidden")

    def __getattr__(self, name: str):
        if not name.startswith("list_"):
            raise AttributeError(name)

        def _list():
            self._guard(name)
            if name == "list_pods":
                return list(self._pods)
            if name == "list_events":
                return [{"metadata": {"uid": "e1"}, "reason": "OOMKilling", "type": "Warning"}]
            if name == "list_secrets_metadata":
                # The factory strips payloads; nothing downstream may reintroduce them.
                return [{"metadata": {"namespace": "prod", "name": "db-password"}, "type": "Opaque"}]
            if name == "list_namespaces":
                return [{"metadata": {"name": "prod", "labels": {}}}]
            if name == "list_cluster_roles":
                return [
                    {
                        "metadata": {"name": "cluster-admin"},
                        "rules": [{"verbs": ["*"], "resources": ["*"]}],
                    }
                ]
            if name == "list_cluster_role_bindings":
                return [
                    {
                        "metadata": {"name": "anon-binding"},
                        "role_ref": {"kind": "ClusterRole", "name": "cluster-admin"},
                        "subjects": [{"kind": "User", "name": "system:anonymous"}],
                    }
                ]
            return []

        return _list

    def read_pod_log(self, ns, pod, container, previous=False):
        self._guard("get pods/log")
        return "" if previous else "app started\n"

    def cluster_version(self):
        self._guard("get /version")
        return {"gitVersion": "v1.30.2", "platform": "linux/amd64"}

    def api_resources(self):
        self._guard("get /apis")
        return {"group_versions": ["v1", "apps/v1"], "groups": [], "resources": {}, "errors": {}}


def _members(archive: Path) -> dict[str, bytes]:
    data = archive.read_bytes()
    if archive.suffix == ".zst":
        import zstandard

        data = zstandard.ZstdDecompressor().decompress(data, max_output_size=200_000_000)
    else:
        data = gzip.decompress(data)
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            if member.isfile():
                out[member.name] = tar.extractfile(member).read()
    return out


def _run(tmp_path: Path, collectors, *, denied=None):
    cfg = KubernetesRunConfig(
        case_id="CASE-K8S-E2E",
        collectors=list(collectors),
        time_window=parse_window(None, None),
        out_dir=tmp_path,
    )
    package = run_kubernetes_collection(cfg, factory=FakeApiPlane(denied=denied))
    return package, _members(package.path)


def test_api_plane_only_run_seals_a_signed_package(tmp_path: Path) -> None:
    package, members = _run(tmp_path, API_PLANE_COLLECTORS)

    assert package.path.exists()
    assert len(package.sha256) == 64
    assert members.get("manifest.json.sig")

    manifest = json.loads(members["manifest.json"])
    assert manifest["cloud"] == "kubernetes"
    assert manifest["case_id"] == "CASE-K8S-E2E"
    assert manifest["account_id"] == "lab-cluster"
    assert manifest["operator"]["user_id"] == "ventra-collector"

    # Every API-plane collector ran and is represented in the manifest.
    assert {s["name"] for s in manifest["sources"]} >= set(API_PLANE_COLLECTORS)

    # Real evidence came back from the API plane even with no node access. A collector
    # writes several files; the record count lives on the events payload, not on config.json.
    events_files = [
        s for s in manifest["sources"] if s["name"] == "k8s_events" and s["path"].endswith("events.jsonl.gz")
    ]
    assert len(events_files) == 1
    assert events_files[0]["record_count"] == 1
    assert all(len(s["sha256"]) == 64 for s in manifest["sources"])

    # audit_posture degrades to a gap (no control-plane node) instead of failing the run.
    posture_gaps = [g for g in manifest["gaps"] if g["name"] == "k8s_audit_posture"]
    assert posture_gaps and posture_gaps[0]["reason"] == "not_present"


def test_one_denied_verb_gaps_that_source_and_the_run_continues(tmp_path: Path) -> None:
    _, members = _run(tmp_path, API_PLANE_COLLECTORS, denied={"list_secrets_metadata"})
    manifest = json.loads(members["manifest.json"])

    denied = [g for g in manifest["gaps"] if g["reason"] == "access_denied"]
    assert any("secrets" in g["detail"] for g in denied)

    # The denied kind is scoped to cluster_state; the other sources still collected.
    statuses = {s["name"]: s["status"] for s in manifest["sources"] if s["path"]}
    assert statuses["k8s_cluster_state"] == "partial"
    assert statuses["k8s_events"] == "collected"
    assert statuses["k8s_rbac"] in ("collected", "partial")
    assert json.loads(members["collection.log"].splitlines()[0])["collector"] == "k8s_events"


def test_missing_audit_log_is_a_critical_gap_linked_to_posture(tmp_path: Path) -> None:
    _, members = _run(tmp_path, ["k8s_apiserver_audit", "k8s_audit_posture"])
    manifest = json.loads(members["manifest.json"])

    audit_gaps = [g for g in manifest["gaps"] if g["name"] == "k8s_apiserver_audit"]
    assert len(audit_gaps) == 1
    assert audit_gaps[0]["reason"] == "logging_not_configured"
    assert "k8s_audit_posture" in audit_gaps[0]["detail"]


def test_sealed_package_never_contains_secret_values(tmp_path: Path) -> None:
    _, members = _run(tmp_path, API_PLANE_COLLECTORS)
    blob = b""
    for name, data in members.items():
        blob += gzip.decompress(data) if name.endswith(".gz") else data

    # Secret metadata is present; the payload keys are nowhere in the evidence.
    assert b"db-password" in blob
    assert b'"data"' not in blob
    assert b"stringData" not in blob
    assert b"string_data" not in blob


def test_node_plane_run_stamps_node_context_and_needs_no_cluster(tmp_path: Path) -> None:
    """A node-plane run works off a mocked host tree with no API server reachable at all."""
    host = tmp_path / "host"
    for rel, content in (
        ("etc/hostname", "cp-1\n"),
        (
            "etc/kubernetes/manifests/kube-apiserver.yaml",
            "    - --audit-log-path=/var/log/kubernetes/audit/audit.log\n",
        ),
        (
            "var/log/kubernetes/audit/audit.log",
            json.dumps(
                {
                    "kind": "Event",
                    "verb": "create",
                    "user": {"username": "mallory"},
                    "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod"},
                }
            )
            + "\n",
        ),
        ("var/log/pods/prod_web_uid1/app/0.log", "container output\n"),
    ):
        path = host / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (host / "var/lib/containerd").mkdir(parents=True, exist_ok=True)

    class NodeOnly(FakeApiPlane):
        """No API server: cluster_identity fails the way an in-cluster node run does."""

        def __init__(self) -> None:
            super().__init__()
            self.node = NodeAccess(root=host, node_name="cp-1")

        def cluster_identity(self):
            raise RuntimeError("no kubeconfig on this node")

    cfg = KubernetesRunConfig(
        case_id="CASE-K8S-NODE",
        collectors=["k8s_apiserver_audit", "k8s_container_logs", "k8s_etcd"],
        time_window=parse_window(None, None),
        out_dir=tmp_path / "out",
        node_root=str(host),
        node_name="cp-1",
    )
    package = run_kubernetes_collection(cfg, factory=NodeOnly())
    members = _members(package.path)
    manifest = json.loads(members["manifest.json"])

    assert manifest["account_id"] == "cp-1"  # falls back to the node's own hostname
    assert manifest["operator"]["principal_arn"] == "kubernetes:node-collector"

    audit_path = next(name for name in members if name.endswith("k8s_apiserver_audit/events.jsonl.gz"))
    record = json.loads(gzip.decompress(members[audit_path]).splitlines()[0])
    assert record["_ventra_node"] == "cp-1"
    assert record["_ventra_runtime"] == "containerd"
    assert record["_ventra_audit_file"] == "/var/log/kubernetes/audit/audit.log"

    # The raw audit log is preserved verbatim alongside the parsed records, and hashed.
    raw = [s for s in manifest["sources"] if s["path"].endswith("k8s_apiserver_audit/audit.log")]
    assert raw and len(raw[0]["sha256"]) == 64
