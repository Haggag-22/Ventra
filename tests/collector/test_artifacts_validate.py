"""Tests for the artifact catalog validator and the `ventra artifacts` CLI."""

from __future__ import annotations

import shutil
from pathlib import Path

from collector.cli import main
from collector.engine.validate import diff_artifacts, validate_artifacts

ARTIFACTS = Path("artifacts")


def test_real_catalog_is_valid() -> None:
    assert validate_artifacts(ARTIFACTS) == []


def test_real_catalog_is_valid_strict() -> None:
    # Every registered collector has a backing YAML and vice versa.
    assert validate_artifacts(ARTIFACTS, strict=True) == []


def test_diff_clean() -> None:
    diff = diff_artifacts(ARTIFACTS)
    for cloud, d in diff.items():
        assert d["missing_yaml"] == [], f"{cloud} collectors without YAML: {d['missing_yaml']}"
        assert d["missing_registry"] == [], f"{cloud} YAML without collector: {d['missing_registry']}"


def _seed(tmp_path: Path, cloud: str) -> Path:
    """Copy one cloud's catalog + packs into a writable temp root."""
    root = tmp_path / "artifacts"
    (root / cloud).mkdir(parents=True)
    for src in (ARTIFACTS / cloud).rglob("*.yaml"):
        dest = root / cloud / src.relative_to(ARTIFACTS / cloud)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    return root


def test_validate_flags_bad_version(tmp_path: Path) -> None:
    root = _seed(tmp_path, "gcp")
    target = next((root / "gcp").rglob("*.yaml"))
    target.write_text(target.read_text().replace("version: 1.0.0", "version: 1.0"), encoding="utf-8")
    errors = validate_artifacts(root, cloud="gcp")
    assert any("version" in e for e in errors)


def test_validate_flags_unknown_collector(tmp_path: Path) -> None:
    root = _seed(tmp_path, "gcp")
    target = root / "gcp" / "bogus.yaml"
    target.write_text(
        "name: GCP.Bogus\ncloud: gcp\ndescription: x\nversion: 1.0.0\n"
        "collector: not_registered\nsources:\n- type: bogus\n",
        encoding="utf-8",
    )
    errors = validate_artifacts(root, cloud="gcp")
    assert any("not in gcp registry" in e for e in errors)


def test_validate_flags_mutating_action(tmp_path: Path) -> None:
    # The read-only guard is AWS-IAM-shaped (service:Verb), so exercise it with an AWS action.
    root = _seed(tmp_path, "aws")
    target = root / "aws" / "bad.yaml"
    target.write_text(
        "name: AWS.Bad\ncloud: aws\ndescription: x\nversion: 1.0.0\n"
        "collector: iam\nrequired_actions:\n- s3:DeleteBucket\nsources:\n- type: x\n",
        encoding="utf-8",
    )
    errors = validate_artifacts(root, cloud="aws")
    assert any("read-only" in e for e in errors)


def test_validate_flags_unexpected_field(tmp_path: Path) -> None:
    root = _seed(tmp_path, "gcp")
    target = next((root / "gcp").rglob("*.yaml"))
    target.write_text(target.read_text() + "surprise: true\n", encoding="utf-8")
    errors = validate_artifacts(root, cloud="gcp")
    assert any("unexpected field" in e for e in errors)


def test_cli_artifacts_validate_exit_zero(capsys) -> None:
    assert main(["artifacts", "validate"]) == 0
    assert "valid" in capsys.readouterr().out


def test_cli_artifacts_list_and_diff(capsys) -> None:
    assert main(["artifacts", "list", "--cloud", "gcp"]) == 0
    out = capsys.readouterr().out
    assert "cloud_audit_admin" in out
    assert main(["artifacts", "diff"]) == 0
