"""Ingest coverage for the on-prem Kubernetes normalizers.

Runs the synthetic Kubernetes demo case through the real pipeline and asserts that each
collector's evidence reaches the unified event store in the shape the console queries — the
audit log's who-did-what, the cluster-state verdicts, the RBAC escalation, the node journals,
and the posture findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_kubernetes_demo_case import generate  # noqa: E402

from ventra_ingester.normalizer.base import NormalizeContext, normalize_source  # noqa: E402
from ventra_ingester.package import EvidencePackage  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


@pytest.fixture(scope="module")
def k8s_case(tmp_path_factory):
    out = tmp_path_factory.mktemp("pkg")
    root = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-TEST-K8S")
    result = ingest_package(pkg, root)
    return result, root, pkg


def _events(root: Path, case_id: str, **filters):
    sys.path.insert(0, str(REPO / "console" / "backend"))
    from app.store import CaseStore, EventQuery

    store = CaseStore(root=root)
    rows = store.query_events(case_id, EventQuery(limit=500))["events"]
    for key, value in filters.items():
        rows = [r for r in rows if r.get(key) == value]
    return rows


# --------------------------------------------------------------------------------------------
# Pipeline wiring
# --------------------------------------------------------------------------------------------
def test_every_kubernetes_source_is_normalized_or_inventoried(k8s_case) -> None:
    result, _root, _pkg = k8s_case
    loaded = set(result.sources_loaded) | set(result.inventory_loaded)
    # Every collector in the package must land somewhere an analyst can see it.
    assert loaded >= {
        "k8s_events",
        "k8s_apiserver_audit",
        "k8s_cluster_state",
        "k8s_rbac",
        "k8s_kubelet_logs",
        "k8s_runtime_logs",
        "k8s_etcd",
        "k8s_audit_posture",
        "k8s_container_logs",
    }
    assert not result.warnings


def test_kubernetes_jsonl_payloads_are_classified_as_events(k8s_case) -> None:
    """The k8s collectors write ``<kind>.jsonl.gz``, not ``events.jsonl.gz``."""
    _result, _root, pkg_path = k8s_case
    with EvidencePackage(pkg_path) as pkg:
        kinds = {
            sf.arcname.rsplit("/", 1)[-1]: sf.kind
            for sf in pkg.source_files()
            if sf.name == "k8s_cluster_state"
        }
    assert kinds["pods.jsonl.gz"] == "events"
    assert kinds["config.json"] == "config"
    # A derived JSON sidecar must not be mistaken for an event payload.
    assert kinds["suspicious_pods.json"] == "other"


# --------------------------------------------------------------------------------------------
# Events — both API groups
# --------------------------------------------------------------------------------------------
def test_events_from_both_apis_normalize_identically(k8s_case) -> None:
    result, root, _pkg = k8s_case
    rows = _events(root, result.case_id, ventra_source="k8s_events")
    by_api = {r["raw"]["_ventra_event_api"] for r in rows}
    assert by_api == {"core/v1", "events.k8s.io/v1"}

    # The events.k8s.io/v1 record uses regarding/note, not involved_object/message — it must
    # still resolve a target and a message rather than coming through blank.
    modern = [r for r in rows if r["raw"]["_ventra_event_api"] == "events.k8s.io/v1"]
    assert modern and all(r["resource_id"] for r in modern)
    assert all(r["message"].strip() and not r["message"].endswith(":") for r in modern)
    assert any("Readiness probe failed" in r["message"] for r in modern)
    assert all(r["timestamp"] for r in modern)


def test_events_severity_raises_the_flagged_reasons(k8s_case) -> None:
    result, root, _pkg = k8s_case
    rows = _events(root, result.case_id, ventra_source="k8s_events")
    by_action = {r["event_action"]: r["event_severity"] for r in rows}
    assert by_action["OOMKilling"] == "high"
    assert by_action["Evicted"] == "high"
    assert by_action["Pulled"] == "info"  # routine, must not crowd the timeline


# --------------------------------------------------------------------------------------------
# Cluster state / RBAC verdicts
# --------------------------------------------------------------------------------------------
def test_suspicious_pod_becomes_a_high_severity_state_event(k8s_case) -> None:
    result, root, _pkg = k8s_case
    pods = _events(root, result.case_id, event_action="PodSnapshot")
    miner = [p for p in pods if p["resource_id"] == "kube-system/kube-proxy-metrics"]
    assert len(miner) == 1
    assert miner[0]["event_severity"] == "high"
    assert miner[0]["event_kind"] == "state"
    for marker in ("privileged:metrics", "hostPID", "hostPath!:/"):
        assert marker in miner[0]["message"]
    # A clean pod stays at info.
    clean = [p for p in pods if p["resource_id"] == "prod/web-7d9f8b6c4-xk2lp"]
    assert clean and clean[0]["event_severity"] == "info"


def test_anonymous_clusterrolebinding_is_critical(k8s_case) -> None:
    result, root, _pkg = k8s_case
    bindings = _events(root, result.case_id, event_action="ClusterRoleBindingSnapshot")
    anon = [b for b in bindings if b["resource_id"] == "system-anon-reader"]
    assert anon and anon[0]["event_severity"] == "critical"
    assert "system:anonymous" in anon[0]["message"]

    escalation = [b for b in bindings if b["resource_id"] == "svc-monitor-admin"]
    assert escalation and escalation[0]["event_severity"] == "high"
    assert "cluster-admin" in escalation[0]["message"]

    benign = [b for b in bindings if b["resource_id"] == "ops-view"]
    assert benign and benign[0]["event_severity"] == "info"


def test_rogue_mutating_webhook_is_high_severity(k8s_case) -> None:
    result, root, _pkg = k8s_case
    hooks = _events(root, result.case_id, event_action="MutatingWebhookSnapshot")
    rogue = [h for h in hooks if h["resource_id"] == "sidecar-injector"]
    assert rogue and rogue[0]["event_severity"] == "high"
    # The off-cluster endpoint must be visible without opening the raw record.
    assert "185.220.101.45" in rogue[0]["message"]


def test_noisy_kinds_are_not_turned_into_timeline_rows(k8s_case) -> None:
    """ConfigMaps/Services/ReplicaSets stay in inventory; they are not timeline events."""
    result, root, _pkg = k8s_case
    actions = {r["event_action"] for r in _events(root, result.case_id,
                                                  ventra_source="k8s_cluster_state")}
    assert "ConfigMapSnapshot" not in actions
    assert "ServiceSnapshot" not in actions


# --------------------------------------------------------------------------------------------
# Node-plane journals
# --------------------------------------------------------------------------------------------
def test_journal_records_get_real_timestamps_and_node_provenance(k8s_case) -> None:
    result, root, _pkg = k8s_case
    rows = _events(root, result.case_id, ventra_source="k8s_kubelet_logs")
    assert rows
    assert all(r["timestamp"].startswith("2026-06-11T") for r in rows)
    # NodeContext survives into the normalized event: the analyst can trace the node.
    assert {r["cloud_region"] for r in rows} == {"worker-2"}
    oom = [r for r in rows if "OOM-killed" in r["message"]]
    assert oom and oom[0]["event_severity"] == "high"


def test_runtime_inspect_rows_become_container_state_not_log_lines(k8s_case) -> None:
    result, root, _pkg = k8s_case
    rows = _events(root, result.case_id, ventra_source="k8s_runtime_logs")
    inspect = [r for r in rows if r["event_action"] == "ContainerRuntimeInspect"]
    assert len(inspect) == 1
    assert inspect[0]["event_kind"] == "state"
    assert inspect[0]["resource_id"] == "kube-system/kube-proxy-metrics/metrics"
    assert inspect[0]["timestamp"]  # collection time, so it lands on the timeline
    # The journal lines from the same source are still events.
    assert any(r["event_kind"] == "event" for r in rows)


def test_posture_snapshots_become_findings_on_the_timeline(k8s_case) -> None:
    result, root, _pkg = k8s_case
    findings = _events(root, result.case_id, event_kind="finding")
    actions = {f["event_action"] for f in findings}
    assert {"AuditLoggingPosture", "EtcdPosture"} <= actions
    assert all(f["timestamp"] for f in findings)

    etcd = [f for f in findings if f["event_action"] == "EtcdPosture"]
    assert etcd and "encryption-at-rest" in etcd[0]["message"]


def test_missing_audit_log_is_a_critical_finding() -> None:
    """The most consequential Kubernetes IR result must surface as critical, not a blank."""
    from ventra_ingester.normalizer.inventory import k8s_posture_events

    ctx = NormalizeContext(case_id="C", account_id="cluster", collected_at="2026-06-11T03:00:00Z")
    snapshot = {"_config": {"audit_enabled": False, "policy_weaknesses": []}}
    events = list(k8s_posture_events("k8s_audit_posture", snapshot, ctx))
    assert len(events) == 1
    assert events[0].event_severity == "critical"
    assert events[0].event_outcome == "failure"
    assert "DISABLED" in events[0].message
    assert events[0].timestamp == "2026-06-11T03:00:00Z"


def test_unknown_kind_is_skipped_rather_than_mis_normalized() -> None:
    ctx = NormalizeContext(case_id="C", account_id="cluster")
    rows = [{"_ventra_kind": "somethingnew", "metadata": {"name": "x"}}]
    assert list(normalize_source("k8s_cluster_state", rows, ctx)) == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
