"""Azure collector registry smoke tests."""

from __future__ import annotations

from collector.engine.registry import AZURE_COLLECTOR_ORDER, AZURE_REGISTRY

EXPECTED = [
    "subscription",
    "entra_signin",
    "entra_audit",
    "entra_directory",
    "activity_log",
    "rbac",
    "unified_audit",
    "unified_audit_search",
    "oauth_consent",
    "defender",
    "vnet_flow",
    "nsg_flow",
    "azure_firewall",
    "app_gateway",
    "front_door",
    "dns",
    "storage_access",
    "key_vault",
    "aks_audit",
    "resource_graph",
    "diag_posture",
    "log_analytics",
]


def test_azure_registry_order() -> None:
    assert list(AZURE_COLLECTOR_ORDER) == EXPECTED


def test_azure_registry_has_all_collectors() -> None:
    names = set(list(AZURE_COLLECTOR_ORDER))
    assert names == set(EXPECTED), f"missing: {set(EXPECTED) - names}"


def test_azure_collectors_declare_readonly_actions() -> None:
    for name, cls in AZURE_REGISTRY.all().items():
        assert cls.required_actions, f"{name} missing required_actions"
        for action in cls.required_actions:
            assert "." in action or ":" in action or "/" in action, f"{name}: odd action {action!r}"
