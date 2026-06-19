"""Host-side credential wiring (AWS profile + Azure SP flags)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from collector.aws.runner.runner import AwsRunConfig, run_aws_collection
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureClientFactory
from collector.azure.runner.runner import AzureRunConfig, run_azure_collection
from collector.lib.auth import azure_factory_kwargs, manifest_profile_overrides
from collector.lib.models import AzureAuthOptions, TimeWindow


def test_manifest_profile_overrides_records_non_secrets() -> None:
    auth = AzureAuthOptions(tenant_id="t-1", client_id="c-1")
    overrides = manifest_profile_overrides(
        aws_profile="client-ro",
        azure_auth=auth,
        subscription_id="sub-a,sub-b",
    )
    assert "aws_profile=client-ro" in overrides
    assert "azure_tenant_id=t-1" in overrides
    assert "azure_client_id=c-1" in overrides
    assert "azure_subscriptions=sub-a,sub-b" in overrides


def test_azure_factory_kwargs_passes_cli_auth() -> None:
    auth = AzureAuthOptions(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
    )
    kwargs = azure_factory_kwargs(auth, subscription_id="sub-1")
    assert kwargs == {
        "subscription_id": "sub-1",
        "tenant_id": "tenant",
        "client_id": "client",
        "client_secret": "secret",
    }


def test_aws_run_uses_named_profile(tmp_path) -> None:
    captured: dict[str, str] = {}

    class _FakeFactory:
        def __init__(self, session) -> None:
            captured["profile"] = session.profile_name

        def caller_identity(self):
            from collector.clouds.aws.client_factory import CallerIdentity

            return CallerIdentity(account_id="123", arn="arn:aws:iam::123:user/x", user_id="A", partition="aws")

        def enabled_regions(self):
            return ["us-east-1"]

    cfg = AwsRunConfig(
        case_id="CASE-1",
        collectors=[],
        regions=["us-east-1"],
        time_window=TimeWindow(),
        out_dir=tmp_path,
        aws_profile="client-readonly",
    )
    fake_session = MagicMock(profile_name="client-readonly")
    with patch("boto3.Session", return_value=fake_session) as session_cls:
        with patch("collector.aws.runner.runner.AwsClientFactory", _FakeFactory):
            with patch("collector.aws.runner.runner.seal_package") as seal:
                seal.return_value = MagicMock(
                    path=tmp_path / "pkg.tar.zst", compression="zst", bytes=1, sha256="0" * 64
                )
                run_aws_collection(cfg)
        session_cls.assert_called_once_with(profile_name="client-readonly")
    assert captured["profile"] == "client-readonly"


def test_azure_run_passes_auth_to_factory(tmp_path) -> None:
    captured: dict[str, object] = {}

    class _FakeFactory:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def caller_identity(self):
            from collector.clouds.azure.client_factory import AzureIdentity

            return AzureIdentity(tenant_id="tenant", principal="client")

        def subscriptions(self):
            return ["sub-1"]

    cfg = AzureRunConfig(
        case_id="CASE-AZ",
        collectors=[],
        regions=[],
        subscription_id="sub-1",
        time_window=TimeWindow(),
        out_dir=tmp_path,
        auth=AzureAuthOptions(tenant_id="tenant", client_id="client", client_secret="s"),
    )
    with patch("collector.azure.runner.runner.AzureClientFactory", _FakeFactory):
        with patch("collector.azure.runner.runner.seal_package") as seal:
            seal.return_value = MagicMock(path=tmp_path / "pkg.tar.zst", compression="zst", bytes=1, sha256="0" * 64)
            run_azure_collection(cfg)
    assert captured["tenant_id"] == "tenant"
    assert captured["client_id"] == "client"
    assert captured["client_secret"] == "s"
    assert captured["subscription_id"] == "sub-1"


def test_azure_client_factory_uses_constructor_overrides() -> None:
    cf = AzureClientFactory(
        credential=object(),
        tenant_id="t",
        client_id="c",
        client_secret="s",
    )
    assert cf._tenant_id_override == "t"
    assert cf._client_id_override == "c"
    assert cf._client_secret_override == "s"
    with patch.object(cf, "graph_get", side_effect=AzureAccessDenied("graph", "no")):
        ident = cf.caller_identity()
    assert ident.tenant_id == "t"
    assert ident.principal == "c"
