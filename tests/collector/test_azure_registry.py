"""Azure collector registry smoke tests."""

from __future__ import annotations

from collector.azure.registry import AZURE_REGISTRY, COLLECTOR_ORDER, all_collector_names

EXPECTED = [
    "subscription",
    "entra_signin",
    "entra_audit",
    "entra_directory",
    "activity_log",
    "rbac",
    "unified_audit",
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
]


def test_azure_registry_order() -> None:
    assert all_collector_names() == EXPECTED
    assert COLLECTOR_ORDER == EXPECTED


def test_azure_registry_has_all_collectors() -> None:
    names = set(all_collector_names())
    assert names == set(EXPECTED), f"missing: {set(EXPECTED) - names}"


def test_azure_collectors_declare_readonly_actions() -> None:
    for name, cls in AZURE_REGISTRY.all().items():
        assert cls.required_actions, f"{name} missing required_actions"
        for action in cls.required_actions:
            assert "." in action or ":" in action or "/" in action, f"{name}: odd action {action!r}"
