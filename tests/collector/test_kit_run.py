"""Tests for Ventra Collection Kit (.kit) format, expiry, run, and import helpers."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from collector.kit.format import (
    KitExpiredError,
    assert_kit_usable,
    load_kit_manifest,
    open_kit,
)
from collector.kit.build import build_kit
from collector.kit.import_cmd import find_evidence_package
from collector.kit.mint import MintedCredential, write_minted_credentials

ARTIFACTS = Path("artifacts")


def test_build_kit_writes_kit_json_and_kit_extension(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "Prod-IR.kit",
        cloud="aws",
        case_id="CASE-KIT-1",
        artifact_names=["guardduty"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
        kit_name="Prod IR",
        connection={
            "platform": "aws",
            "auth_method": "profile",
            "profile_name": "ir-readonly",
        },
    )
    assert out.suffix == ".kit"
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "kit.json" in names
        assert "acquisition.yaml" in names
        assert "README.md" in names
        assert not any(n.endswith(".py") for n in names if n != "kit.json")
        kit = json.loads(zf.read("kit.json"))
    assert kit["format"] == "ventra.kit"
    assert kit["case_id"] == "CASE-KIT-1"
    assert kit["kit_name"] == "Prod IR"
    assert "guardduty" in kit["collectors"]
    assert kit["expires_at"]
    assert kit["credential"]["provider"] == "aws"


def test_open_kit_and_expiry_fail_fast(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "acquisition.yaml").write_text("case_id: CASE-X\ncloud: aws\nartifacts: []\n")
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    kit_json = {
        "format": "ventra.kit",
        "format_version": "1",
        "kit_id": "abc",
        "case_id": "CASE-X",
        "cloud": "aws",
        "ventra_version": "0.0.0",
        "created_at": past,
        "expires_at": past,
        "collectors": [],
        "credential": {
            "provider": "aws",
            "kind": "sts_session",
            "expires_at": past,
            "path": "credentials/aws.json",
        },
    }
    (staging / "kit.json").write_text(json.dumps(kit_json))
    out = tmp_path / "expired.kit"
    with zipfile.ZipFile(out, "w") as zf:
        for path in staging.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(staging).as_posix())

    with open_kit(out) as kit:
        with pytest.raises(KitExpiredError, match="expired"):
            assert_kit_usable(kit.manifest)


def test_load_kit_manifest_requires_fields() -> None:
    with pytest.raises(Exception, match="missing"):
        load_kit_manifest({"format": "ventra.kit"})


def test_write_minted_credentials(tmp_path: Path) -> None:
    minted = MintedCredential(
        provider="aws",
        kind="sts_session",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        files={"credentials/aws.json": '{"aws_access_key_id":"A","aws_secret_access_key":"B","aws_session_token":"C"}\n'},
        acquisition_fields={"aws_credentials": "credentials/aws.json"},
    )
    write_minted_credentials(tmp_path, minted)
    assert (tmp_path / "credentials" / "aws.json").is_file()
    assert (tmp_path / "credentials" / "meta.json").is_file()


def test_mint_rejects_expired_k8s_jwt() -> None:
    from collector.kit.mint import mint_connection_credentials
    import base64

    past = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    payload = base64.urlsafe_b64encode(json.dumps({"exp": past}).encode()).decode().rstrip("=")
    token = f"eyJhbGciOiJub25lIn0.{payload}."
    with pytest.raises(ValueError, match="expired"):
        mint_connection_credentials(
            {
                "platform": "kubernetes",
                "k8s_context": "lab",
                "kubeconfig_content": (
                    "apiVersion: v1\nkind: Config\n"
                    "clusters: [{name: c, cluster: {server: https://127.0.0.1}}]\n"
                    "contexts: [{name: lab, context: {cluster: c, user: u}}]\n"
                    f"users: [{{name: u, user: {{token: {token}}}}}]\n"
                    "current-context: lab\n"
                ),
            },
            cloud="kubernetes",
        )


def test_find_evidence_package_prefers_direct(tmp_path: Path) -> None:
    pkg = tmp_path / "case-CASE-1-acct-20260101T000000Z.tar.zst"
    pkg.write_bytes(b"not-a-real-archive")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "older.tar.zst").write_bytes(b"x")
    found = find_evidence_package(tmp_path)
    assert found == pkg


def test_build_legacy_zip_still_ships_entry_script(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "legacy.zip",
        cloud="aws",
        case_id="CASE-LEGACY",
        artifact_names=["guardduty"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
        kit_name="Legacy Zip",
    )
    with zipfile.ZipFile(out) as zf:
        assert "kit.json" in zf.namelist()
        assert "Legacy-Zip.py" in zf.namelist()
        assert "run.sh" in zf.namelist()
