"""Tests for the acquisition spec + pack loader and collector resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from collector.engine.acquisition import (
    AcquisitionError,
    artifact_refs_for_collectors,
    list_packs,
    load_acquisition,
    load_pack,
    resolve_collectors_from_acquisition,
)

ARTIFACTS = Path("artifacts")


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "acquisition.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_pack_returns_collector_keys() -> None:
    keys = load_pack("baseline-ir-gcp", ARTIFACTS)
    assert "cloud_audit_admin" in keys
    assert "scc_findings" in keys


def test_load_pack_unknown_raises() -> None:
    with pytest.raises(AcquisitionError):
        load_pack("does-not-exist", ARTIFACTS)


def test_list_packs_filtered_by_cloud() -> None:
    gcp = list_packs("gcp", ARTIFACTS)
    assert [p["pack"] for p in gcp] == ["baseline-ir-gcp"]
    assert gcp[0]["artifacts"], "pack should carry its collector keys"
    assert {p["cloud"] for p in list_packs(None, ARTIFACTS)} == {"aws", "azure", "gcp"}


def test_load_acquisition_full_form(tmp_path: Path) -> None:
    spec = load_acquisition(_write(tmp_path, """
case_id: CASE-1
cloud: gcp
ventra_version: "0.4.0"
artifacts:
  - collector: cloud_audit_admin
    name: GCP.ManagementPlane.CloudAuditAdmin
    version: "1.0.0"
    parameters: { since: "30d" }
"""))
    assert spec.case_id == "CASE-1"
    assert spec.cloud == "gcp"
    assert spec.ventra_version == "0.4.0"
    assert spec.artifacts[0].collector == "cloud_audit_admin"
    assert spec.artifacts[0].parameters == {"since": "30d"}


def test_load_acquisition_short_form(tmp_path: Path) -> None:
    spec = load_acquisition(_write(tmp_path, """
case_id: CASE-2
cloud: gcp
artifacts: [cloud_audit_admin, vpc_flow]
"""))
    assert [a.collector for a in spec.artifacts] == ["cloud_audit_admin", "vpc_flow"]


def test_load_acquisition_global_filters(tmp_path: Path) -> None:
    spec = load_acquisition(_write(tmp_path, """
case_id: CASE-F
cloud: aws
since: 2026-05-01
until: 2026-06-01
regions: [us-east-1, us-west-2]
max_records_per_source: 0
artifacts:
  - collector: cloudtrail
    parameters: { since: "30d" }
"""))
    assert spec.since == "2026-05-01"
    assert spec.until == "2026-06-01"
    assert spec.regions == ["us-east-1", "us-west-2"]
    assert spec.max_records_per_source == 0
    assert spec.artifact_parameters() == {"cloudtrail": {"since": "30d"}}


def test_load_acquisition_requires_cloud(tmp_path: Path) -> None:
    with pytest.raises(AcquisitionError):
        load_acquisition(_write(tmp_path, "case_id: X\nartifacts: []\n"))


def test_resolve_enriches_and_orders(tmp_path: Path) -> None:
    spec = load_acquisition(_write(tmp_path, """
case_id: CASE-3
cloud: gcp
artifacts: [scc_findings, project]
"""))
    names, refs = resolve_collectors_from_acquisition(spec, ARTIFACTS)
    # project precedes scc_findings in registry order, regardless of spec order.
    assert names == ["project", "scc_findings"]
    by = {r.collector: r for r in refs}
    assert by["project"].name == "GCP.Identity.Project"
    assert by["project"].version == "1.0.0"


def test_resolve_pack_plus_explicit_override(tmp_path: Path) -> None:
    spec = load_acquisition(_write(tmp_path, """
case_id: CASE-4
cloud: gcp
pack: baseline-ir-gcp
artifacts:
  - collector: cloud_audit_admin
    name: Custom.Name
    version: "9.9.9"
    parameters: { since: "7d" }
"""))
    names, refs = resolve_collectors_from_acquisition(spec, ARTIFACTS)
    by = {r.collector: r for r in refs}
    # Explicit entry overrides the pack's plain entry for the same collector.
    assert by["cloud_audit_admin"].name == "Custom.Name"
    assert by["cloud_audit_admin"].version == "9.9.9"
    assert by["cloud_audit_admin"].parameters == {"since": "7d"}
    # And the rest of the pack is still present.
    assert "scc_findings" in names


def test_resolve_unknown_collector_raises(tmp_path: Path) -> None:
    spec = load_acquisition(_write(tmp_path, """
case_id: CASE-5
cloud: gcp
artifacts: [not_a_real_collector]
"""))
    with pytest.raises(AcquisitionError, match="unknown collector"):
        resolve_collectors_from_acquisition(spec, ARTIFACTS)


def test_artifact_refs_for_collectors() -> None:
    refs = artifact_refs_for_collectors("gcp", ["cloud_audit_admin", "vpc_flow"], ARTIFACTS)
    assert [r.collector for r in refs] == ["cloud_audit_admin", "vpc_flow"]
    assert all(r.version.count(".") == 2 for r in refs)
    assert refs[0].name == "GCP.ManagementPlane.CloudAuditAdmin"


def test_artifacts_root_from_kit_acquisition(tmp_path: Path, monkeypatch) -> None:
    from collector.cli import _artifacts_root_from_args, _collection_plan_label

    kit = tmp_path / "kit"
    art = kit / "artifacts"
    art.mkdir(parents=True)
    acq = kit / "acquisition.yaml"
    acq.write_text("cloud: aws\ncase_id: T\nartifacts:\n- collector: guardduty\n")

    class Args:
        acquisition = str(acq)
        pack = ""
        collectors = ""

    monkeypatch.delenv("VENTRA_ARTIFACTS_ROOT", raising=False)
    assert _artifacts_root_from_args(Args()) == art
    assert "1 artifacts from acquisition.yaml" in _collection_plan_label(Args(), ["guardduty"])
