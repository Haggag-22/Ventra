"""GCP collector registry smoke tests."""

from __future__ import annotations

from collector.engine.registry import GCP_COLLECTOR_ORDER, GCP_REGISTRY

EXPECTED = [
    "project",
    "iam_policy",
    "cloud_audit_admin",
    "cloud_audit_system",
    "cloud_audit_data",
    "logging_posture",
    "login_events",
    "vpc_flow",
    "firewall_logs",
    "cloud_nat",
    "network_posture",
    "load_balancer",
    "cloud_cdn",
    "api_gateway",
    "cloud_dns",
    "cloud_armor",
    "vm_logs",
    "gce",
    "cloud_functions",
    "gke_audit",
    "storage_access",
    "bigquery_audit",
    "cloud_sql",
    "secret_manager",
    "scc_findings",
    "cloud_monitoring",
]


def test_gcp_registry_order() -> None:
    assert list(GCP_COLLECTOR_ORDER) == EXPECTED


def test_gcp_registry_has_all_collectors() -> None:
    names = set(list(GCP_COLLECTOR_ORDER))
    assert names == set(EXPECTED), f"missing: {set(EXPECTED) - names}"


def test_gcp_collectors_declare_readonly_actions() -> None:
    for name, cls in GCP_REGISTRY.all().items():
        assert cls.required_actions, f"{name} missing required_actions"
        for action in cls.required_actions:
            assert "." in action or ":" in action or "/" in action, f"{name}: odd action {action!r}"


def test_gcp_engine_list_collectors() -> None:
    from pathlib import Path

    from collector.engine.executor import list_collectors
    from collector.engine.loader import load_artifacts_dir

    assert list_collectors("gcp") == EXPECTED
    arts = load_artifacts_dir(Path("artifacts"), cloud="gcp")
    assert len(arts) == len(EXPECTED)
    assert {a["collector"] for a in arts} == set(EXPECTED)
