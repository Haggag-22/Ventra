"""Per-cloud registry lazy loading."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


from collector.kit.build import build_kit

ARTIFACTS = Path("artifacts")


def test_aws_registry_does_not_import_gcp_modules() -> None:
    code = """
import sys
from collector.engine.registry import registry_for_cloud
registry_for_cloud("aws")
blocked = [m for m in sys.modules if m.startswith(("google", "azure"))]
assert not blocked, f"unexpected imports: {blocked}"
"""
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_build_kit_aws_requirements_exclude_other_cloud_sdks(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="aws",
        case_id="CASE-AWS-DEPS",
        artifact_names=["guardduty"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        reqs = zf.read("requirements.txt").decode().lower()
    assert "boto3" in reqs
    assert "google-cloud" not in reqs
    assert "google-auth" not in reqs
    assert "azure-" not in reqs


def test_build_kit_gcp_requirements_exclude_aws_and_azure_sdks(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="gcp",
        case_id="CASE-GCP-DEPS",
        artifact_names=["cloud_audit_admin"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        reqs = zf.read("requirements.txt").decode().lower()
    assert "google-cloud-logging" in reqs
    assert "boto3" not in reqs
    assert "azure-" not in reqs


def test_build_kit_azure_requirements_exclude_aws_and_gcp_sdks(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="azure",
        case_id="CASE-AZ-DEPS",
        artifact_names=["activity_log"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
    )
    with zipfile.ZipFile(out) as zf:
        reqs = zf.read("requirements.txt").decode().lower()
    assert "azure-identity" in reqs
    assert "requests" in reqs
    assert "boto3" not in reqs
    assert "google-cloud" not in reqs
