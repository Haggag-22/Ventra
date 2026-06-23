"""Tests for the acquisition kit builder and the `ventra kit build` CLI."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
import yaml

from collector.cli import main
from collector.engine.acquisition import load_acquisition, resolve_collectors_from_acquisition
from collector.kit.build import _bundle_wheel, _download_pypi_wheel, build_kit
from collector.kit.preview import preview_kit

ARTIFACTS = Path("artifacts")
IAM = Path("docs/iam-policies")


def test_build_kit_full_schema_acquisition(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="gcp",
        case_id="CASE-KIT",
        artifact_names=["cloud_audit_admin", "scc_findings"],
        artifacts_root=ARTIFACTS,
        since="2026-05-01",
        until="2026-06-01",
        regions=["us-central1"],
        max_records_per_source=50000,
        artifact_parameters={"cloud_audit_admin": {"since": "30d"}},
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "acquisition.yaml" in names
        assert "run.sh" in names
        acq = yaml.safe_load(zf.read("acquisition.yaml"))

    assert acq["cloud"] == "gcp"
    assert acq["case_id"] == "CASE-KIT"
    assert acq["since"] == "2026-05-01"
    assert acq["until"] == "2026-06-01"
    assert acq["regions"] == ["us-central1"]
    assert acq["max_records_per_source"] == 50000
    assert acq["ventra_version"]
    entry = {a["collector"]: a for a in acq["artifacts"]}
    assert set(entry) == {"cloud_audit_admin", "scc_findings"}
    assert entry["cloud_audit_admin"]["name"] == "GCP.ManagementPlane.CloudAuditAdmin"
    assert entry["cloud_audit_admin"]["parameters"] == {"since": "30d"}
    assert "vpc_flow" not in entry


def test_kit_acquisition_roundtrips(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="gcp",
        case_id="CASE-RT",
        artifact_names=["cloud_audit_admin", "vpc_flow"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
    )
    extracted = tmp_path / "acquisition.yaml"
    with zipfile.ZipFile(out) as zf:
        extracted.write_bytes(zf.read("acquisition.yaml"))
    spec = load_acquisition(extracted)
    names, _ = resolve_collectors_from_acquisition(spec, ARTIFACTS)
    assert names == ["cloud_audit_admin", "vpc_flow"]


def test_build_kit_narrows_iam(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="gcp",
        case_id="CASE-IAM",
        artifact_names=["scc_findings"],  # only needs securitycenter.findings.list
        artifacts_root=ARTIFACTS,
        iam_policy_paths=[IAM / "gcp-collector-readonly.json"],
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        policy = json.loads(zf.read("iam/gcp-collector-readonly.json"))
    assert policy["permissions"] == ["securitycenter.findings.list"]


def test_build_kit_no_match_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no artifacts matched"):
        build_kit(
            tmp_path / "kit.zip",
            cloud="gcp",
            case_id="X",
            artifact_names=["nope"],
            artifacts_root=ARTIFACTS,
        )


def test_cli_kit_build(tmp_path: Path, capsys) -> None:
    out = tmp_path / "kit.zip"
    code = main(["kit", "build", "--cloud", "gcp", "--pack", "baseline-ir-gcp",
                 "--case", "CASE-CLI", "--out", str(out)])
    assert code == 0
    assert out.is_file()
    with zipfile.ZipFile(out) as zf:
        assert "acquisition.yaml" in zf.namelist()
        assert "iam/gcp-collector-readonly.json" in zf.namelist()


def test_cli_list_packs(capsys) -> None:
    assert main(["collect", "gcp", "--list-packs"]) == 0
    assert "baseline-ir-gcp" in capsys.readouterr().out


def test_kit_ships_ventra_py_and_requirements(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="aws",
        case_id="CASE-FLAGS",
        artifact_names=["guardduty"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "ventra.py" in names
        assert "requirements.txt" in names
        ventra_py = zf.read("ventra.py").decode()
        reqs = zf.read("requirements.txt").decode()
        run_sh = zf.read("run.sh").decode()
    assert "--profile" in ventra_py
    assert "--subscription" in ventra_py
    assert "--project" in ventra_py
    assert "PyYAML" in reqs
    assert "ventra.py" in run_sh


def test_build_kit_deployment_profile_ec2(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="aws",
        case_id="CASE-EC2",
        artifact_names=["guardduty"],
        artifacts_root=ARTIFACTS,
        deployment_profile="ec2",
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "deployment-profile.txt" in names
        assert "ec2-bootstrap.sh" in names
        profile_txt = zf.read("deployment-profile.txt").decode()
        assert profile_txt.startswith("profile: ec2")
        assert "TRADEOFFS" in profile_txt
        acq = yaml.safe_load(zf.read("acquisition.yaml"))
        readme = zf.read("README-operator.md").decode()
    assert acq["deployment_profile"] == "ec2"
    assert "EC2 collector instance" in readme
    assert "Tradeoffs (read before you run)" in readme


def test_build_kit_cloudshell_tradeoffs_in_profile_txt(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="aws",
        case_id="CASE-CS",
        artifact_names=["guardduty"],
        artifacts_root=ARTIFACTS,
        deployment_profile="cloudshell",
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        profile_txt = zf.read("deployment-profile.txt").decode()
        readme = zf.read("README-operator.md").decode()
    assert "does NOT pull all records" in profile_txt.lower() or "Does NOT pull all records" in profile_txt
    assert "Tradeoffs (read before you run)" in readme


def test_bundle_wheel_source_first_in_dev_clone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    order: list[str] = []

    def fake_pypi(dist: Path, version: str) -> bool:
        order.append("pypi")
        return False

    def fake_source(dist: Path) -> bool:
        order.append("source")
        (dist / "ventra-test-py3-none-any.whl").write_bytes(b"")
        return True

    monkeypatch.setattr("collector.kit.build._is_source_checkout", lambda: True)
    monkeypatch.setattr("collector.kit.build._download_pypi_wheel", fake_pypi)
    monkeypatch.setattr("collector.kit.build._wheel_from_source_tree", fake_source)
    staging = tmp_path / "staging"
    staging.mkdir()
    _bundle_wheel(staging, required=True)
    assert order == ["source"]
    assert list((staging / "dist").glob("ventra-*.whl"))


def test_bundle_wheel_pypi_first_outside_clone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    order: list[str] = []

    def fake_pypi(dist: Path, version: str) -> bool:
        order.append("pypi")
        return False

    def fake_source(dist: Path) -> bool:
        order.append("source")
        (dist / "ventra-test-py3-none-any.whl").write_bytes(b"")
        return True

    monkeypatch.setattr("collector.kit.build._is_source_checkout", lambda: False)
    monkeypatch.setattr("collector.kit.build._download_pypi_wheel", fake_pypi)
    monkeypatch.setattr("collector.kit.build._wheel_from_source_tree", fake_source)
    staging = tmp_path / "staging"
    staging.mkdir()
    _bundle_wheel(staging, required=True)
    assert order == ["pypi", "source"]


def test_preview_kit_iam_narrowing() -> None:
    preview = preview_kit(
        cloud="gcp",
        artifact_names=["scc_findings"],
        artifacts_root=ARTIFACTS,
        iam_policy_paths=[IAM / "gcp-collector-readonly.json"],
    )
    assert preview["artifact_count"] == 1
    assert preview["iam_action_count"] == 1
    assert preview["iam_actions"] == ["securitycenter.findings.list"]
    assert "gcp-collector-readonly.json" in preview["iam_policies"]
    assert preview["iam_policies"]["gcp-collector-readonly.json"]["permissions"] == [
        "securitycenter.findings.list"
    ]
