"""Console coverage for on-prem Kubernetes cases.

Ingests the synthetic Kubernetes demo case and checks that the panels the console renders
actually populate for a ``cloud: kubernetes`` manifest — the case summary, the cluster
timeline, Data Access (Secret reads), the Resource Inventory roll-ups, and Logs Coverage.
Before this, a Kubernetes case fell through to the AWS layout and showed empty EC2/S3 rows.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))
sys.path.insert(0, str(REPO / "console" / "backend"))

from generate_kubernetes_demo_case import generate  # noqa: E402

from app.store import CaseStore, EventQuery  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


@pytest.fixture(scope="module")
def k8s_store_case(tmp_path_factory) -> tuple[CaseStore, str]:
    out = tmp_path_factory.mktemp("pkg")
    root = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-TEST-STORE-K8S")
    result = ingest_package(pkg, root)
    return CaseStore(root=root), result.case_id


def test_case_summary_identifies_the_cluster(k8s_store_case) -> None:
    store, case_id = k8s_store_case
    summary = store.summary(case_id)
    assert summary["cloud"] == "kubernetes"
    assert summary["account_id"] == "prod-k8s-onprem"
    assert summary["account_alias"] == "v1.30.2"  # server version
    # Every collector that produced events is represented, so the case header counts match.
    assert set(summary["by_source"]) >= {
        "k8s_apiserver_audit", "k8s_events", "k8s_cluster_state", "k8s_rbac",
        "k8s_kubelet_logs", "k8s_runtime_logs",
        "k8s_etcd", "k8s_audit_posture",
    }
    assert summary["by_severity"].get("critical", 0) >= 1
    assert summary["integrity"]


def test_cluster_timeline_reconstructs_the_attack_sequence(k8s_store_case) -> None:
    """The build spec's end-to-end criterion: exec → secret → RBAC → miner, in order."""
    store, case_id = k8s_store_case
    rows = store.query_events(case_id, EventQuery(limit=500))["events"]
    audit = sorted(
        (r for r in rows if r["ventra_source"] == "k8s_apiserver_audit" and r["timestamp"]),
        key=lambda r: r["timestamp"],
    )
    actions = [r["event_action"] for r in audit]

    def idx(action: str) -> int:
        return actions.index(action)

    assert idx("create pods/exec") < idx("get secrets")
    assert idx("get secrets") < idx("create clusterrolebindings")
    assert idx("create clusterrolebindings") < idx("create pods/portforward")

    # The miner pod's own state event sits on the same timeline as the audit entry that
    # created it, which is what makes the two correlatable.
    miner = [r for r in rows if r["resource_id"] == "kube-system/kube-proxy-metrics"
             and r["event_action"] == "PodSnapshot"]
    assert miner and miner[0]["timestamp"]


def test_data_access_panel_shows_secret_reads(k8s_store_case) -> None:
    store, case_id = k8s_store_case
    da = store.data_access_overview(case_id)
    assert da["totals"]["events"] > 0
    assert [s["source"] for s in da["by_source"]] == ["k8s_apiserver_audit"]
    principals = {p["principal"] for p in da["top_principals"]}
    # The compromised ServiceAccount is what actually read the Secrets.
    assert "system:serviceaccount:prod:web-runner" in principals


def test_resource_inventory_uses_the_kubernetes_rollups(k8s_store_case) -> None:
    store, case_id = k8s_store_case
    inv = store.inventory_summary(case_id)
    names = [c["name"] for c in inv["categories"]]
    assert names == ["Workloads", "Cluster & storage", "Identity & admission",
                     "Flagged for review"]
    # No AWS rows leak into a Kubernetes case.
    ids = {i["id"] for c in inv["categories"] for i in c["items"]}
    assert all(i.startswith("k8s_") for i in ids)
    assert not {"ec2_instances", "s3_buckets", "iam_users"} & ids

    counts = {i["id"]: i["count"] for c in inv["categories"] for i in c["items"]}
    assert counts["k8s_pods"] == 3
    assert counts["k8s_clusterrolebindings"] == 3
    assert counts["k8s_suspicious_pods"] == 2
    assert counts["k8s_anonymous_bindings"] == 1
    assert inv["total_resources"] > 0


def test_resource_inventory_rows_carry_the_collector_verdicts(k8s_store_case) -> None:
    """The panel renders rows, so each spec must resolve to a list — not a count."""
    store, case_id = k8s_store_case
    state = store.inventory(case_id, "k8s_cluster_state")

    pods = state["objects"]["pods"]
    assert len(pods) == 3
    miner = next(p for p in pods if p["name"] == "kube-proxy-metrics")
    assert miner["namespace"] == "kube-system"
    assert miner["node"] == "worker-2"
    assert "privileged:metrics" in miner["flags"]
    assert "xmrig" in miner["images"]
    # The compact index must not drag the full pod spec into the case store.
    assert "spec" not in miner and "status" not in miner

    crbs = state.get("objects", {})
    rbac = store.inventory(case_id, "k8s_rbac")["objects"]["clusterrolebindings"]
    anon = next(b for b in rbac if b["name"] == "system-anon-reader")
    assert anon["anonymous"] == "system:anonymous"
    assert "cluster-admin" in anon["grants"]
    assert crbs is not None


def test_inventory_snapshots_keep_the_derived_artefacts(k8s_store_case) -> None:
    store, case_id = k8s_store_case
    state = store.inventory(case_id, "k8s_cluster_state")
    assert state["_config"]["counts"]["pods"] == 3
    assert state["pod_security"]["privileged_namespaces"] == ["gatekeeper-system"]
    assert state["environment"]["cluster"]["gitVersion"] == "v1.30.2"
    # Secret values are never present anywhere in the case store.
    import json

    blob = json.dumps(state)
    assert '"data"' not in blob and "stringData" not in blob

    posture = store.inventory(case_id, "k8s_audit_posture")
    assert posture["_config"]["audit_enabled"] is True
    assert posture["_config"]["policy_weaknesses"]


def test_collection_log_and_gaps_are_available_for_the_coverage_panel(k8s_store_case) -> None:
    store, case_id = k8s_store_case
    log = store.collection_log(case_id)
    assert log and log[0]["collector"] == "k8s_events"  # volatility order preserved

    gaps = store.manifest(case_id)["gaps"]
    reasons = {g["reason"] for g in gaps}
    assert "logging_not_configured" in reasons  # weak audit policy + etcd at-rest
    joined = " ".join(g["detail"] for g in gaps)
    assert "encryption" in joined.lower() or "audit" in joined.lower()


def test_event_facets_let_an_analyst_pivot_on_the_cluster(k8s_store_case) -> None:
    store, case_id = k8s_store_case
    facets = store.facets(case_id, EventQuery(limit=500))

    sources = {f["value"] for f in facets.get("ventra_source", [])}
    assert {"k8s_apiserver_audit", "k8s_cluster_state", "k8s_events"} <= sources

    # Subjects: the human, the compromised ServiceAccount, and the anonymous probe.
    users = {f["value"] for f in facets.get("user_name", [])}
    assert {"mallory@contractor.example", "system:serviceaccount:prod:web-runner",
            "system:anonymous"} <= users

    # Where it came from, and which node the node-plane evidence belongs to.
    assert "203.0.113.66" in {f["value"] for f in facets.get("source_ip", [])}
    assert {"worker-2", "cp-1"} <= {f["value"] for f in facets.get("cloud_region", [])}

    actions = {f["value"] for f in facets.get("event_action", [])}
    assert "create pods/exec" in actions
    assert "PodSnapshot" in actions


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
