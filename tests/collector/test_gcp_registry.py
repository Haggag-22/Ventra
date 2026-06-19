"""GCP collector registry smoke tests."""

from __future__ import annotations

from collector.gcp.registry import COLLECTOR_ORDER, GCP_REGISTRY, all_collector_names

EXPECTED = [
    "project",
    "iam_policy",
    "cloud_audit_admin",
    "cloud_audit_system",
    "cloud_audit_data",
    "login_events",
    "workspace_audit",
    "vpc_flow",
    "firewall_logs",
    "load_balancer",
    "api_gateway",
    "vm_logs",
    "cloud_functions",
    "storage_access",
    "scc_findings",
    "cloud_monitoring",
]


def test_gcp_registry_order() -> None:
    assert all_collector_names() == EXPECTED
    assert COLLECTOR_ORDER == EXPECTED


def test_gcp_registry_has_all_collectors() -> None:
    names = set(all_collector_names())
    assert names == set(EXPECTED), f"missing: {set(EXPECTED) - names}"


def test_gcp_collectors_declare_readonly_actions() -> None:
    for name, cls in GCP_REGISTRY.all().items():
        assert cls.required_actions, f"{name} missing required_actions"
        for action in cls.required_actions:
            assert "." in action or ":" in action or "/" in action, f"{name}: odd action {action!r}"
