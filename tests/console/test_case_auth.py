"""The authentication a case was collected with is recorded end to end (run → manifest → summary)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from collector.engine.acquisition import load_acquisition
from collector.engine.api.aws.runner import AwsRunConfig, _auth_ref
from collector.engine.run_launcher import RunLaunchRequest
from collector.kit.auth_embed import embed_connection_auth
from collector.lib.models import AuthRef, Manifest, Operator, TimeWindow
from ventra_ingester.loaders.casestore import build_summary

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "backend"))

import app.run_service as run_service  # noqa: E402


def _manifest(auth: AuthRef | None) -> Manifest:
    return Manifest(
        schema_version="1.0.0",
        tool_version="0",
        case_id="CASE-AUTH",
        cloud="aws",
        account_id="111122223333",
        regions=[],
        operator=Operator(principal_arn="arn:aws:iam::111122223333:user/ir"),
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:00Z",
        profile_name="all",
        host_environment="local",
        auth=auth,
    )


def test_manifest_records_auth_and_schema_allows_it() -> None:
    out = _manifest(AuthRef(name="Prod IR role", method="assume_role", connection_id="c-1")).to_dict()
    assert out["auth"] == {"name": "Prod IR role", "method": "assume_role", "connection_id": "c-1"}
    assert out["profile"]["name"] == "all"

    schema = json.loads((REPO / "schemas" / "manifest.schema.json").read_text())
    assert set(out) <= set(schema["properties"])
    assert set(out["auth"]) <= set(schema["properties"]["auth"]["properties"])


def test_manifest_omits_empty_auth() -> None:
    assert "auth" not in _manifest(None).to_dict()
    assert "auth" not in _manifest(AuthRef()).to_dict()


def test_cli_run_without_connection_records_profile_or_method(tmp_path: Path) -> None:
    base = dict(case_id="C", collectors=[], regions=None, time_window=TimeWindow(), out_dir=tmp_path)
    assert _auth_ref(AwsRunConfig(**base, aws_profile="ir-prod")) == AuthRef(name="ir-prod", method="profile")
    assert _auth_ref(AwsRunConfig(**base)) == AuthRef(method="default")
    kit = AuthRef(name="Kit conn", method="assume_role")
    assert _auth_ref(AwsRunConfig(**base, aws_profile="x", auth_ref=kit)) is kit


def test_kit_acquisition_records_connection_not_minted_method(tmp_path: Path) -> None:
    acq: dict = {"cloud": "aws"}
    conn = {
        "id": "conn-42",
        "name": "Client AWS (read-only)",
        "platform": "aws",
        "auth_method": "credentials",
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "secret",
    }
    embed_connection_auth(tmp_path, conn, acq)
    assert acq["auth"] == {
        "name": "Client AWS (read-only)",
        "method": "credentials",
        "connection_id": "conn-42",
    }
    assert "secret" not in json.dumps(acq["auth"])

    acq_path = tmp_path / "acquisition.yaml"
    acq_path.write_text(f"cloud: aws\nauth:\n  name: {conn['name']!r}\n  method: assume_role\n")
    spec = load_acquisition(acq_path)
    assert spec.auth == AuthRef(name="Client AWS (read-only)", method="assume_role")


def test_acquisition_without_auth_is_none(tmp_path: Path) -> None:
    p = tmp_path / "acquisition.yaml"
    p.write_text("cloud: aws\n")
    assert load_acquisition(p).auth is None


def test_console_run_records_saved_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Store:
        def get_connection(self, _id: str) -> dict:
            return {"id": "conn-7", "name": "IR workstation", "platform": "aws", "auth_method": "profile"}

    monkeypatch.setattr(run_service, "config_store", _Store())
    req = run_service._apply_connection(RunLaunchRequest(cloud="aws", case_id="C"), "conn-7")
    assert req.auth_ref == AuthRef(name="IR workstation", method="profile", connection_id="conn-7")


def test_summary_carries_auth_and_old_manifests_default_empty() -> None:
    manifest = _manifest(AuthRef(name="IR workstation", method="profile")).to_dict()
    assert build_summary(manifest, {}, [])["auth"] == {"name": "IR workstation", "method": "profile"}
    manifest.pop("auth")
    assert build_summary(manifest, {}, [])["auth"] == {}
