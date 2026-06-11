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

from collector.aws.client_factory import AwsClientFactory  # noqa: E402
from collector.aws.registry import all_collector_names  # noqa: E402
from collector.aws.runner.runner import (  # noqa: E402
    AwsRunConfig,
    parse_window,
    run_aws_collection,
)


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
def test_full_collection_produces_valid_package(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}))

    cfg = AwsRunConfig(
        case_id="CASE-TEST-0001",
        collectors=all_collector_names(),
        regions=["us-east-1"],
        time_window=parse_window("2026-01-01", None),
        out_dir=tmp_path,
    )

    package = run_aws_collection(cfg, factory=AwsClientFactory(boto3.Session()))

    assert package.path.exists()
    assert len(package.sha256) == 64

    manifest = json.loads(_read_member(package.path, "manifest.json"))
    assert manifest["case_id"] == "CASE-TEST-0001"
    assert manifest["cloud"] == "aws"
    assert manifest["account_id"]
    assert manifest["operator"]["principal_arn"]
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["profile"]["name"] == "all"
    assert {s["name"] for s in manifest["sources"]}

    sig = _read_member(package.path, "manifest.json.sig")
    assert sig

    names = {s["name"] for s in manifest["sources"]}
    assert "account" in names


@mock_aws
def test_gap_is_recorded_not_fatal(tmp_path: Path) -> None:
    """A service with nothing configured must surface as a gap, and the run must still seal."""
    cfg = AwsRunConfig(
        case_id="CASE-TEST-0002",
        collectors=all_collector_names(),
        regions=["us-east-1"],
        time_window=parse_window(None, None),
        out_dir=tmp_path,
    )
    package = run_aws_collection(cfg, factory=AwsClientFactory(boto3.Session()))
    manifest = json.loads(_read_member(package.path, "manifest.json"))
    assert "gaps" in manifest
