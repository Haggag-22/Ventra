"""Kit expiry: 7-day kit limit, longest safe credential per cloud, honest ``expires``."""

from __future__ import annotations

import base64
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from collector.kit import mint
from collector.kit.build import build_kit
from collector.kit.format import (
    KitExpiredError,
    assert_kit_usable,
    human_duration,
    load_kit_manifest,
    short_remaining,
)
from collector.kit.run_view import expiry_lines

WEEK = 7 * 24 * 3600


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "VENTRA_KIT_TTL_SECONDS",
        "VENTRA_KIT_AWS_DURATION_SECONDS",
        "VENTRA_KIT_STATIC_SECRET_TTL_SECONDS",
    ):
        monkeypatch.delenv(key, raising=False)


def _hours_from_now(dt: datetime) -> float:
    return (dt - datetime.now(timezone.utc)).total_seconds() / 3600


def _validation_error(op: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "ValidationError", "Message": "The requested DurationSeconds exceeds the limit"}},
        op,
    )


class _FakeSts:
    def __init__(self, *, max_session: int = 129600, max_role: int = 43200) -> None:
        self.max_session = max_session
        self.max_role = max_role
        self.asked: list[int] = []

    def _creds(self, duration: int) -> dict[str, Any]:
        return {
            "Credentials": {
                "AccessKeyId": "ASIATEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime.now(timezone.utc) + timedelta(seconds=duration),
            }
        }

    def get_session_token(self, DurationSeconds: int) -> dict[str, Any]:  # noqa: N803
        self.asked.append(DurationSeconds)
        if DurationSeconds > self.max_session:
            raise _validation_error("GetSessionToken")
        return self._creds(DurationSeconds)

    def assume_role(self, *, RoleArn: str, RoleSessionName: str, DurationSeconds: int) -> dict[str, Any]:  # noqa: N803
        self.asked.append(DurationSeconds)
        if DurationSeconds > self.max_role:
            raise _validation_error("AssumeRole")
        return self._creds(DurationSeconds)


def _patch_boto(monkeypatch: pytest.MonkeyPatch, sts: Any, frozen: Any = None) -> None:
    class _Session:
        def __init__(self, **_: Any) -> None:
            pass

        def client(self, name: str) -> Any:
            assert name == "sts"
            return sts

        def get_credentials(self) -> Any:
            return frozen

    monkeypatch.setattr(boto3, "Session", _Session)


_KEYS = {
    "platform": "aws",
    "auth_method": "credentials",
    "aws_access_key_id": "AKIA",
    "aws_secret_access_key": "s",
}


def test_default_kit_limit_is_seven_days() -> None:
    assert mint.kit_ttl_seconds() == WEEK


def test_kit_limit_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENTRA_KIT_TTL_SECONDS", "7200")
    assert mint.kit_ttl_seconds() == 7200


def test_aws_session_token_asks_for_36_hours(monkeypatch: pytest.MonkeyPatch) -> None:
    sts = _FakeSts()
    _patch_boto(monkeypatch, sts)
    minted = mint.mint_connection_credentials(_KEYS, cloud="aws")
    assert sts.asked == [129600]
    assert minted.kind == "sts_session"
    assert minted.details["limited_by"] == "credential"
    assert 35.9 < _hours_from_now(minted.expires_at) <= 36
    assert "36 hours" in minted.details["lifetime_note"]


def test_aws_session_token_root_falls_back_to_one_hour(monkeypatch: pytest.MonkeyPatch) -> None:
    sts = _FakeSts(max_session=3600)
    _patch_boto(monkeypatch, sts)
    minted = mint.mint_connection_credentials(_KEYS, cloud="aws")
    assert sts.asked == [129600, 3600]
    assert 0.9 < _hours_from_now(minted.expires_at) <= 1


def test_aws_assume_role_uses_role_max_session(monkeypatch: pytest.MonkeyPatch) -> None:
    sts = _FakeSts(max_role=4 * 3600)
    _patch_boto(monkeypatch, sts)
    conn = {**_KEYS, "role_arn": "arn:aws:iam::123456789012:role/ir"}
    minted = mint.mint_connection_credentials(conn, cloud="aws")
    assert sts.asked == [43200, 28800, 21600, 14400]
    assert minted.kind == "sts_assume_role"
    assert minted.details["limited_by"] == "credential"
    assert 3.9 < _hours_from_now(minted.expires_at) <= 4


def test_aws_duration_env_caps_the_ask(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENTRA_KIT_AWS_DURATION_SECONDS", "7200")
    sts = _FakeSts()
    _patch_boto(monkeypatch, sts)
    mint.mint_connection_credentials(_KEYS, cloud="aws")
    assert sts.asked == [7200]


def test_aws_non_duration_error_does_not_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Denied(_FakeSts):
        def get_session_token(self, DurationSeconds: int) -> dict[str, Any]:  # noqa: N803
            self.asked.append(DurationSeconds)
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetSessionToken")

    sts = _Denied()
    frozen = SimpleNamespace(access_key="AKIA", secret_key="s", token=None)
    _patch_boto(monkeypatch, sts, frozen)
    minted = mint.mint_connection_credentials(_KEYS, cloud="aws")
    assert sts.asked == [129600]
    # Static keys stay on the short limit; they never stretch a kit to 7 days.
    assert minted.kind == "static_ttl"
    assert minted.details["limited_by"] == "static_secret"
    assert 3.9 < _hours_from_now(minted.expires_at) <= 4


def test_aws_reused_session_expiry_is_upper_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    frozen = SimpleNamespace(access_key="ASIA", secret_key="s", token="t")
    _patch_boto(monkeypatch, _FakeSts(), frozen)
    minted = mint.mint_connection_credentials({**_KEYS, "aws_session_token": "t"}, cloud="aws")
    assert minted.details["expiry_is_upper_bound"] is True
    assert minted.details["limited_by"] == "credential"
    assert 35.9 < _hours_from_now(minted.expires_at) <= 36


def test_aws_profile_without_embed_gets_full_kit_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_: Any) -> Any:
        raise RuntimeError("no profile")

    monkeypatch.setattr(boto3, "Session", _boom)
    minted = mint.mint_connection_credentials(
        {"platform": "aws", "auth_method": "profile", "profile_name": "ir"}, cloud="aws"
    )
    assert minted.files == {}
    assert minted.details["limited_by"] == "kit"
    assert _hours_from_now(minted.expires_at) > 7 * 24 - 0.1


_SA = {"type": "service_account", "client_email": "ir@p.iam.gserviceaccount.com", "project_id": "p"}


def test_gcp_extended_token_sets_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    exp = datetime.now(timezone.utc) + timedelta(hours=12)
    monkeypatch.setattr(mint, "_gcp_mint_token", lambda sa: ("tok", exp, 43200))
    minted = mint.mint_connection_credentials(
        {"platform": "gcp", "gcp_service_account_json": json.dumps(_SA)}, cloud="gcp"
    )
    assert minted.kind == "access_token"
    assert minted.expires_at == exp
    assert minted.details["limited_by"] == "credential"
    assert "12 hours" in minted.details["lifetime_note"]


def test_gcp_token_failure_keeps_short_static_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(sa: dict[str, Any]) -> Any:
        raise RuntimeError("offline")

    monkeypatch.setattr(mint, "_gcp_mint_token", _fail)
    minted = mint.mint_connection_credentials(
        {"platform": "gcp", "gcp_service_account_json": json.dumps(_SA)}, cloud="gcp"
    )
    assert minted.details["limited_by"] == "static_secret"
    assert _hours_from_now(minted.expires_at) <= 4


def test_gcp_adc_gets_full_kit_limit() -> None:
    minted = mint.mint_connection_credentials({"platform": "gcp", "auth_method": "adc"}, cloud="gcp")
    assert minted.details["limited_by"] == "kit"
    assert _hours_from_now(minted.expires_at) > 7 * 24 - 0.1


_AZ = {
    "platform": "azure",
    "azure_tenant_id": "t",
    "azure_client_id": "c",
    "azure_client_secret": "s",
}


def test_azure_token_expiry_is_kit_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    expires_on = int((datetime.now(timezone.utc) + timedelta(minutes=75)).timestamp())
    monkeypatch.setattr(
        mint, "_azure_mint_token", lambda *a, **k: SimpleNamespace(token="tok", expires_on=expires_on)
    )
    minted = mint.mint_connection_credentials(_AZ, cloud="azure")
    assert minted.kind == "access_token"
    assert int(minted.expires_at.timestamp()) == expires_on
    assert minted.details["limited_by"] == "credential"


def test_azure_certificate_only_mints_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    expires_on = int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp())

    def _token(tenant: str, client: str, *, secret: str, cert: str) -> Any:
        seen.update(secret=secret, cert=cert)
        return SimpleNamespace(token="tok", expires_on=expires_on)

    monkeypatch.setattr(mint, "_azure_mint_token", _token)
    conn = {**_AZ, "azure_client_secret": "", "azure_client_certificate_content": "PEM"}
    minted = mint.mint_connection_credentials(conn, cloud="azure")
    assert seen == {"secret": "", "cert": "PEM"}
    assert minted.kind == "access_token"


def _jwt(exp: datetime | None) -> str:
    def b64(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    payload = {"sub": "system:serviceaccount:ir:ventra"}
    if exp is not None:
        payload["exp"] = int(exp.timestamp())
    return f"{b64({'alg': 'RS256'})}.{b64(payload)}.sig"


def _kubeconfig(user: dict[str, Any]) -> str:
    return json.dumps(
        {
            "apiVersion": "v1",
            "current-context": "c",
            "contexts": [{"name": "c", "context": {"cluster": "k", "user": "u"}}],
            "clusters": [{"name": "k", "cluster": {"server": "https://k"}}],
            "users": [{"name": "u", "user": user}],
        }
    )


def _k8s(user: dict[str, Any]) -> mint.MintedCredential:
    return mint.mint_connection_credentials(
        {"platform": "kubernetes", "kubeconfig_content": _kubeconfig(user)}, cloud="kubernetes"
    )


def test_k8s_long_token_reaches_seven_days() -> None:
    minted = _k8s({"token": _jwt(datetime.now(timezone.utc) + timedelta(days=10))})
    assert minted.details["limited_by"] == "kit"
    assert _hours_from_now(minted.expires_at) > 7 * 24 - 0.1


def test_k8s_short_token_limits_the_kit() -> None:
    exp = (datetime.now(timezone.utc) + timedelta(days=2)).replace(microsecond=0)
    minted = _k8s({"token": _jwt(exp)})
    assert minted.details["limited_by"] == "credential"
    assert minted.expires_at == exp


def test_k8s_token_without_expiry_is_static() -> None:
    minted = _k8s({"token": _jwt(None)})
    assert minted.details["limited_by"] == "static_secret"
    assert _hours_from_now(minted.expires_at) <= 4


def test_k8s_client_certificate_is_static() -> None:
    minted = _k8s({"client-certificate-data": "Y2VydA==", "client-key-data": "a2V5"})
    assert minted.details["limited_by"] == "static_secret"


def test_k8s_exec_plugin_uses_kit_limit() -> None:
    minted = _k8s({"exec": {"command": "aws", "args": ["eks", "get-token"]}})
    assert minted.details["limited_by"] == "kit"


def test_build_kit_readme_explains_expiry_and_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sts = _FakeSts(max_role=3600)
    _patch_boto(monkeypatch, sts)
    out = build_kit(
        tmp_path / "IR.kit",
        cloud="aws",
        case_id="CASE-EXP",
        artifact_names=["guardduty"],
        artifacts_root=Path("artifacts"),
        bundle_wheel=False,
        kit_name="IR",
        connection={**_KEYS, "role_arn": "arn:aws:iam::1:role/ir"},
    )
    with zipfile.ZipFile(out) as zf:
        kit = json.loads(zf.read("kit.json"))
        readme = zf.read("README.md").decode()
    assert kit["expires_at"] == kit["credential"]["expires_at"]
    assert kit["credential"]["limited_by"] == "credential"
    assert "ventra run IR.kit --out ./evidence" in readme
    assert "\nventra run IR.kit\n" not in readme
    assert "Ventra's kit limit (7 days) is longer" in readme
    assert "AssumeRole" in readme


def _manifest(limited_by: str, *, hours: float, upper: bool = False) -> Any:
    exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cred: dict[str, Any] = {
        "provider": "aws",
        "expires_at": exp,
        "limited_by": limited_by,
        "kit_ttl_seconds": WEEK,
    }
    if upper:
        cred["expiry_is_upper_bound"] = True
    return load_kit_manifest(
        {
            "kit_id": "k",
            "case_id": "C",
            "cloud": "aws",
            "ventra_version": "1",
            "created_at": exp,
            "expires_at": exp,
            "credential": cred,
        }
    )


def test_expiry_lines_say_when_credential_is_the_limit() -> None:
    lines = expiry_lines(_manifest("credential", hours=36))
    assert len(lines) == 2
    assert "(in 1d 11h)" in lines[0] or "(in 1d 12h)" in lines[0]
    assert lines[1] == "Set by the AWS credential's lifetime; the kit itself allows 7 days."


def test_expiry_lines_kit_limit_has_no_note() -> None:
    assert len(expiry_lines(_manifest("kit", hours=7 * 24))) == 1


def test_expiry_lines_static_and_upper_bound() -> None:
    assert "long-lived AWS secret" in expiry_lines(_manifest("static_secret", hours=4))[1]
    assert "at the latest" in expiry_lines(_manifest("credential", hours=36, upper=True))[0]


def test_expired_credential_refuses_even_if_kit_limit_is_later() -> None:
    manifest = _manifest("credential", hours=-1)
    manifest.expires_at = (datetime.now(timezone.utc) + timedelta(days=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(KitExpiredError, match="Download a fresh kit"):
        assert_kit_usable(manifest)


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(WEEK, "7 days"), (129600, "36 hours"), (3600, "1 hour"), (900, "15 minutes"), (5400, "1h 30m")],
)
def test_human_duration(seconds: int, text: str) -> None:
    assert human_duration(seconds) == text


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(WEEK - 60, "6d 23h"), (43140, "11h 59m"), (2520, "42m"), (10, "<1m")],
)
def test_short_remaining(seconds: int, text: str) -> None:
    assert short_remaining(seconds) == text
