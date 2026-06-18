"""CLI --collectors flag tests."""

from __future__ import annotations

import pytest

from collector.cli import _resolve_collectors


def test_resolve_collectors_defaults_to_all() -> None:
    all_names = ["a", "b", "c"]
    registry = type("R", (), {"all": staticmethod(lambda: {"a": 1, "b": 2, "c": 3})})()
    assert _resolve_collectors("", all_names, registry) == all_names


def test_resolve_collectors_subset_in_stable_order() -> None:
    all_names = ["activity_log", "entra_signin", "rbac"]
    registry = type("R", (), {"all": staticmethod(lambda: dict.fromkeys(all_names, 1))})()
    assert _resolve_collectors("rbac,activity_log", all_names, registry) == ["activity_log", "rbac"]


def test_resolve_collectors_unknown_raises() -> None:
    all_names = ["activity_log"]
    registry = type("R", (), {"all": staticmethod(lambda: {"activity_log": 1})})()
    with pytest.raises(ValueError, match="Unknown collector"):
        _resolve_collectors("nope", all_names, registry)
