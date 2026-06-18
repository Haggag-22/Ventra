"""Build cloud client factories from CLI / run-config auth options."""

from __future__ import annotations

from typing import Any

from ..lib.models import AzureAuthOptions


def azure_factory_kwargs(
    auth: AzureAuthOptions,
    *,
    subscription_id: str | None,
) -> dict[str, Any]:
    """Keyword args for :class:`~collector.azure.client_factory.AzureClientFactory`."""
    kwargs: dict[str, Any] = {"subscription_id": subscription_id}
    if auth.tenant_id:
        kwargs["tenant_id"] = auth.tenant_id
    if auth.client_id:
        kwargs["client_id"] = auth.client_id
    if auth.client_secret:
        kwargs["client_secret"] = auth.client_secret
    if auth.client_certificate_path:
        kwargs["client_certificate_path"] = auth.client_certificate_path
    if auth.client_certificate_password:
        kwargs["client_certificate_password"] = auth.client_certificate_password
    return kwargs


def manifest_profile_overrides(*, aws_profile: str = "", azure_auth: AzureAuthOptions | None = None,
                               subscription_id: str | None = None) -> list[str]:
    """Non-secret acquisition context recorded in the manifest."""
    overrides: list[str] = []
    if aws_profile:
        overrides.append(f"aws_profile={aws_profile}")
    if azure_auth and azure_auth.tenant_id:
        overrides.append(f"azure_tenant_id={azure_auth.tenant_id}")
    if azure_auth and azure_auth.client_id:
        overrides.append(f"azure_client_id={azure_auth.client_id}")
    if subscription_id:
        overrides.append(f"azure_subscriptions={subscription_id}")
    return overrides
