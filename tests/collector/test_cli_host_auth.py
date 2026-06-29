"""CLI host-auth helper tests."""

from __future__ import annotations

import argparse

from collector.cli import _azure_auth_from_args, _azure_subscription_from_args


def test_azure_auth_from_args_prefers_flags(monkeypatch) -> None:
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    args = argparse.Namespace(
        tenant_id="flag-tenant",
        client_id="flag-client",
        client_secret="flag-secret",
        client_certificate="",
        subscription="sub-1",
    )
    auth = _azure_auth_from_args(args)
    assert auth.tenant_id == "flag-tenant"
    assert auth.client_id == "flag-client"
    assert auth.client_secret == "flag-secret"


def test_azure_auth_from_args_falls_back_to_env(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_TENANT_ID", "env-tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "env-client")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "env-secret")
    args = argparse.Namespace(
        tenant_id="",
        client_id="",
        client_secret="",
        client_certificate="",
        subscription="",
    )
    auth = _azure_auth_from_args(args)
    assert auth.tenant_id == "env-tenant"
    assert auth.client_id == "env-client"
    assert auth.client_secret == "env-secret"


def test_azure_subscription_from_args(monkeypatch) -> None:
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    args = argparse.Namespace(subscription="aaa,bbb")
    assert _azure_subscription_from_args(args, None) == "aaa,bbb"
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "from-env")
    args = argparse.Namespace(subscription="")
    assert _azure_subscription_from_args(args, None) == "from-env"
