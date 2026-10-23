"""Tests for ``ventra run`` delivering the sealed package via the kit's transport."""

from __future__ import annotations

import argparse
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from collector.engine.acquisition import load_acquisition
from collector.kit import run as kit_run
from collector.kit.deliver import (
    deliver_package,
    kit_transport,
    redact_transport,
)
from collector.kit.format import KitError
from collector.lib.transport import Transport
from collector.lib.transport.base import S3PresignedTransport, S3Transport

PRESIGNED = "s3-presigned:https://ir-bucket.s3.amazonaws.com/drop/pkg.tar.zst?X-Amz-Signature=sekrit"


def _acq(tmp_path: Path, transport: str | None) -> Path:
    path = tmp_path / "acquisition.yaml"
    body = "case_id: CASE-T\ncloud: aws\nartifacts: []\n"
    if transport is not None:
        body += f"transport: {json.dumps(transport)}\n"
    path.write_text(body)
    return path


def test_load_acquisition_reads_transport(tmp_path: Path) -> None:
    assert load_acquisition(_acq(tmp_path, "s3://ir/drop/")).transport == "s3://ir/drop/"
    assert load_acquisition(_acq(tmp_path, None)).transport == ""


@pytest.mark.parametrize("spec", [None, "", "local"])
def test_kit_transport_local_means_no_delivery(tmp_path: Path, spec: str | None) -> None:
    assert kit_transport(_acq(tmp_path, spec))[1] is None


def test_kit_transport_parses_console_specs(tmp_path: Path) -> None:
    spec, transport = kit_transport(_acq(tmp_path, "s3://ir-bucket/case-1/"))
    assert spec == "s3://ir-bucket/case-1/"
    assert isinstance(transport, S3Transport)
    assert (transport.bucket, transport.prefix) == ("ir-bucket", "case-1")
    _, transport = kit_transport(_acq(tmp_path, PRESIGNED))
    assert isinstance(transport, S3PresignedTransport)


def test_kit_transport_rejects_unknown_spec(tmp_path: Path) -> None:
    with pytest.raises(KitError, match="invalid transport"):
        kit_transport(_acq(tmp_path, "ftp://nope"))


def test_redact_transport_drops_presigned_signature() -> None:
    redacted = redact_transport(PRESIGNED)
    assert "sekrit" not in redacted
    assert redacted == "s3-presigned:https://ir-bucket.s3.amazonaws.com/drop/pkg.tar.zst"
    assert redact_transport("s3://ir/drop/") == "s3://ir/drop/"


class _EnvRecorder(Transport):
    """Records the AWS env the upload ran under."""

    def __init__(self, error: Exception | None = None) -> None:
        self.seen: dict[str, str | None] = {}
        self.error = error

    def deliver(self, package_path: Path) -> str:
        self.seen = {k: os.environ.get(k) for k in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE")}
        if self.error:
            raise self.error
        return f"delivered {package_path.name}"


def test_deliver_uses_host_credentials_then_restores_kit_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "KIT-READONLY")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    pkg = tmp_path / "pkg.tar.zst"
    pkg.write_bytes(b"x")
    transport = _EnvRecorder()

    out = deliver_package(transport, "local-test", pkg, host_aws_env={"AWS_PROFILE": "operator"})

    assert out.location == "delivered pkg.tar.zst" and out.error == ""
    assert transport.seen == {"AWS_ACCESS_KEY_ID": None, "AWS_PROFILE": "operator"}
    assert os.environ["AWS_ACCESS_KEY_ID"] == "KIT-READONLY"
    assert "AWS_PROFILE" not in os.environ


def test_deliver_reports_failure_without_raising(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg.tar.zst"
    pkg.write_bytes(b"x")
    out = deliver_package(_EnvRecorder(RuntimeError("AccessDenied")), PRESIGNED, pkg, host_aws_env={})
    assert out.error == "AccessDenied"
    assert out.location == ""
    assert "sekrit" not in out.target
    assert pkg.is_file()


def test_s3_delivery_gets_a_fresh_session_from_host_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import boto3

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "KIT-READONLY")
    created: list[str | None] = []

    class _Session:
        def __init__(self) -> None:
            created.append(os.environ.get("AWS_ACCESS_KEY_ID"))

    monkeypatch.setattr(boto3.session, "Session", _Session)
    transport = S3Transport("ir-bucket", "drop")
    monkeypatch.setattr(S3Transport, "deliver", lambda self, p: f"s3://{self.bucket}/x")
    pkg = tmp_path / "pkg.tar.zst"
    pkg.write_bytes(b"x")

    out = deliver_package(transport, "s3://ir-bucket/drop", pkg, host_aws_env={"AWS_ACCESS_KEY_ID": "HOST"})

    assert out.location == "s3://ir-bucket/x"
    assert created == ["HOST"]
    assert isinstance(transport.session, _Session)


# --- run_kit_file end to end (collection stubbed) ---------------------------------------


def _write_kit(tmp_path: Path, transport: str | None) -> Path:
    staging = tmp_path / "staging"
    (staging / "credentials").mkdir(parents=True)
    _acq(staging, transport)
    (staging / "credentials" / "aws.json").write_text(
        json.dumps({"aws_access_key_id": "KIT-AK", "aws_secret_access_key": "KIT-SK"})
    )
    now = datetime.now(timezone.utc)
    stamp = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    later = stamp(now + timedelta(hours=2))
    (staging / "kit.json").write_text(
        json.dumps(
            {
                "format": "ventra.kit",
                "format_version": "1",
                "kit_id": "kit-deliver",
                "case_id": "CASE-T",
                "cloud": "aws",
                "ventra_version": "0.0.0",
                "created_at": stamp(now),
                "expires_at": later,
                "collectors": ["guardduty"],
                "credential": {
                    "provider": "aws",
                    "kind": "sts_session",
                    "expires_at": later,
                    "path": "credentials/aws.json",
                },
            }
        )
    )
    out = tmp_path / "deliver.kit"
    with zipfile.ZipFile(out, "w") as zf:
        for path in staging.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(staging).as_posix())
    return out


@pytest.fixture
def stub_collection(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Replace the engine with one that writes a fake sealed package under ``out_dir``."""
    calls: list[dict[str, Any]] = []
    # run_kit_file exports the kit's keys; set-then-delete so monkeypatch restores them after.
    for key in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "VENTRA_ARTIFACTS_ROOT",
    ):
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key)

    def _fake(*, out_dir: Path, **kwargs: Any):
        calls.append(kwargs)
        pkg = out_dir / "case-CASE-T-acct-20260101T000000Z.tar.zst"
        pkg.write_bytes(b"sealed")
        return SimpleNamespace(path=pkg), [{"collector": "guardduty", "status": "ok"}]

    monkeypatch.setattr(kit_run, "_execute_collection", _fake)
    return calls


def test_run_kit_delivers_when_kit_sets_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_collection: list
) -> None:
    sent: list[Path] = []

    def _put(self: S3PresignedTransport, package_path: Path) -> str:
        sent.append(package_path)
        return "uploaded to presigned URL (HTTP 200)"

    monkeypatch.setattr(S3PresignedTransport, "deliver", _put)
    out = tmp_path / "evidence"

    result = kit_run.run_kit_file(_write_kit(tmp_path, PRESIGNED), out_dir=out)

    assert result.success
    assert result.delivered_to == "uploaded to presigned URL (HTTP 200)"
    assert result.delivery_error == ""
    assert sent == [result.package_path]
    custody = json.loads((out / "cli_run.json").read_text())
    assert custody["transport"]["location"] == "uploaded to presigned URL (HTTP 200)"
    assert "sekrit" not in json.dumps(custody)


def test_run_kit_without_transport_stays_local(tmp_path: Path, stub_collection: list) -> None:
    out = tmp_path / "evidence"
    result = kit_run.run_kit_file(_write_kit(tmp_path, None), out_dir=out)
    assert result.success
    assert (result.transport, result.delivered_to, result.delivery_error) == ("", "", "")
    assert "transport" not in json.loads((out / "cli_run.json").read_text())


def test_run_kit_bad_transport_fails_before_collecting(tmp_path: Path, stub_collection: list) -> None:
    result = kit_run.run_kit_file(_write_kit(tmp_path, "ftp://nope"), out_dir=tmp_path / "ev")
    assert not result.success
    assert "invalid transport" in result.error
    assert stub_collection == []


def test_cli_run_exits_nonzero_when_delivery_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_collection: list
) -> None:
    from collector.cli import _run_kit_file

    def _fail(self: S3PresignedTransport, package_path: Path) -> str:
        raise RuntimeError("HTTP Error 403: Forbidden")

    monkeypatch.setattr(S3PresignedTransport, "deliver", _fail)
    kit = _write_kit(tmp_path, PRESIGNED)
    out = tmp_path / "evidence"
    args = argparse.Namespace(kit=str(kit), out=str(out), no_sudo=True)

    assert _run_kit_file(args) == 1
    custody = json.loads((out / "cli_run.json").read_text())
    assert custody["status"] == "completed"
    assert custody["transport"]["error"] == "HTTP Error 403: Forbidden"
    assert (out / "case-CASE-T-acct-20260101T000000Z.tar.zst").is_file()
