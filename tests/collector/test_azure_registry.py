"""Azure collector registry smoke tests."""

from __future__ import annotations

from collector.azure.registry import AZURE_REGISTRY, all_collector_names

EXPECTED = {
    "subscription",
    "activity_log",
    "entra_signin",
    "entra_audit",
    "rbac",
    "nsg_flow",
    "defender",
}


def test_azure_registry_has_tier1_collectors() -> None:
    names = set(all_collector_names())
    assert names == EXPECTED


def test_azure_collectors_declare_readonly_actions() -> None:
    for name, cls in AZURE_REGISTRY.all().items():
        assert cls.required_actions, f"{name} missing required_actions"
        for action in cls.required_actions:
            assert "." in action or ":" in action or "/" in action, f"{name}: odd action {action!r}"
