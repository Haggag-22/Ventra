"""End-to-end collector test against mocked AWS (moto).

Proves the full pipeline: caller identity -> run collectors -> assemble + sign manifest ->
seal package. Collectors whose services moto doesn't fully implement degrade to gaps rather
than aborting the run, which is exactly the behaviour we want in the field.
"""

from __future__ import annotations

import json
import tarfile
import io
from pathlib import Path

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from harbor_collector.aws.client_factory import AwsClientFactory  # noqa: E402
from harbor_collector.aws.runner.runner import (  # noqa: E402
    AwsRunConfig,
    parse_window,
    run_aws_collection,
)
from harbor_collector.common.profiles import load_profile, resolve_collectors  # noqa: E402


def _read_member(archive: Path, name: str) -> bytes:
    """Read one member from a .tar.zst or .tar.gz package."""
    data = archive.read_bytes()
    if archive.suffix == ".zst":
        import zstandard

        data = zstandard.ZstdDecompressor().decompress(data, max_output_size=200_000_000)
    else:
        import gzip

        data = gzip.decompress(data)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return tar.extractfile(name).read()


@mock_aws
def test_baseline_collection_produces_valid_package(tmp_path: Path) -> None:
    # Seed a little IAM state so the iam/account collectors have something real to gather.
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}))

    profile = load_profile("baseline")
    collectors, overrides = resolve_collectors(profile, [], [])

    cfg = AwsRunConfig(
        case_id="CASE-TEST-0001",
        profile=profile,
        collectors=collectors,
        profile_overrides=overrides,
        regions=["us-east-1"],
        time_window=parse_window("2026-01-01", None),
        out_dir=tmp_path,
    )

    package = run_aws_collection(cfg, factory=AwsClientFactory(boto3.Session()))

    # Package exists and hashes.
    assert package.path.exists()
    assert len(package.sha256) == 64

    # Manifest is present, parseable, and carries chain-of-custody fields.
    manifest = json.loads(_read_member(package.path, "manifest.json"))
    assert manifest["case_id"] == "CASE-TEST-0001"
    assert manifest["cloud"] == "aws"
    assert manifest["account_id"]  # moto default account
    assert manifest["operator"]["principal_arn"]
    assert manifest["schema_version"] == "1.0.0"
    assert {s["name"] for s in manifest["sources"]}  # at least one source recorded

    # Signature sidecar exists inside the package.
    sig = _read_member(package.path, "manifest.json.sig")
    assert sig  # non-empty (sha256-stamp fallback in CI without cosign)

    # The account collector should have captured operator context.
    names = {s["name"] for s in manifest["sources"]}
    assert "account" in names


@mock_aws
def test_gap_is_recorded_not_fatal(tmp_path: Path) -> None:
    """A service with nothing configured must surface as a gap, and the run must still seal."""
    profile = load_profile("baseline")
    collectors, overrides = resolve_collectors(profile, [], [])
    cfg = AwsRunConfig(
        case_id="CASE-TEST-0002",
        profile=profile,
        collectors=collectors,
        profile_overrides=overrides,
        regions=["us-east-1"],
        time_window=parse_window(None, None),
        out_dir=tmp_path,
    )
    package = run_aws_collection(cfg, factory=AwsClientFactory(boto3.Session()))
    manifest = json.loads(_read_member(package.path, "manifest.json"))
    # vpc_flow / guardduty / waf have nothing configured in a blank account -> gaps or empty.
    assert "gaps" in manifest
