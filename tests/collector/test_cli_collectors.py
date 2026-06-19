"""CLI --collectors flag tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from collector.cli import _plan_collection, _resolve_collectors, build_parser
from collector.engine.registry import GCP_COLLECTOR_ORDER, GCP_REGISTRY


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


def _gcp_args(extra: list[str]):
    return build_parser().parse_args(["collect", "gcp", *extra])


def test_plan_collection_pack() -> None:
    names, refs, case_id, eng, spec = _plan_collection(
        _gcp_args(["--pack", "baseline-ir-gcp"]), "gcp", list(GCP_COLLECTOR_ORDER), GCP_REGISTRY
    )
    assert "cloud_audit_admin" in names
    assert {r.collector for r in refs} == set(names)
    assert all(r.version for r in refs)
    assert case_id == "" and eng == "" and spec is None


def test_plan_collection_acquisition(tmp_path: Path) -> None:
    acq = tmp_path / "acquisition.yaml"
    acq.write_text(
        "case_id: CASE-ACQ\ncloud: gcp\nartifacts: [scc_findings, project]\n", encoding="utf-8"
    )
    names, refs, case_id, eng, spec = _plan_collection(
        _gcp_args(["--acquisition", str(acq)]), "gcp", list(GCP_COLLECTOR_ORDER), GCP_REGISTRY
    )
    assert names == ["project", "scc_findings"]
    assert case_id == "CASE-ACQ"
    assert spec is not None and spec.case_id == "CASE-ACQ"


def test_plan_collection_acquisition_cloud_mismatch(tmp_path: Path) -> None:
    acq = tmp_path / "acquisition.yaml"
    acq.write_text("case_id: X\ncloud: aws\nartifacts: [cloudtrail]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        _plan_collection(
            _gcp_args(["--acquisition", str(acq)]), "gcp", list(GCP_COLLECTOR_ORDER), GCP_REGISTRY
        )


def test_plan_collection_default_collectors() -> None:
    names, refs, case_id, eng, spec = _plan_collection(
        _gcp_args([]), "gcp", list(GCP_COLLECTOR_ORDER), GCP_REGISTRY
    )
    assert names == list(GCP_COLLECTOR_ORDER)
    assert len(refs) == len(names)
    assert spec is None
