"""Build cloud client factories from CLI / run-config auth options."""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path
from typing import Any

from ..lib.models import AzureAuthOptions

_CERT_FILES: list[Path] = []


def materialize_client_certificate(content: str) -> Path:
    """Write base64 or PEM certificate content to a temp file for Azure SDK auth."""
    raw = content.strip()
    if not raw:
        raise ValueError("Certificate content is empty.")
    data: bytes
    suffix = ".pem"
    try:
        decoded = base64.b64decode(raw, validate=True)
        data = decoded
        if decoded.startswith(b"-----BEGIN"):
            suffix = ".pem"
        elif decoded[:2] == b"MI" or decoded.startswith(b"0\x82"):
            suffix = ".pfx"
    except Exception:
        data = raw.encode("utf-8")
        if raw.startswith("-----BEGIN"):
            suffix = ".pem"
    fd, path_str = tempfile.mkstemp(suffix=suffix, prefix="ventra-azure-cert-")
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    path = Path(path_str)
    _CERT_FILES.append(path)
    return path


def azure_factory_kwargs(
    auth: AzureAuthOptions,
    *,
    subscription_id: str | None,
) -> dict[str, Any]:
    """Keyword args for :class:`~collector.clouds.azure.client_factory.AzureClientFactory`."""
    kwargs: dict[str, Any] = {"subscription_id": subscription_id}
    if auth.tenant_id:
        kwargs["tenant_id"] = auth.tenant_id
    if auth.client_id:
        kwargs["client_id"] = auth.client_id
    if auth.client_secret:
        kwargs["client_secret"] = auth.client_secret
    cert_path = auth.client_certificate_path.strip()
    if not cert_path and auth.client_certificate_content.strip():
        cert_path = str(materialize_client_certificate(auth.client_certificate_content))
    if cert_path:
        kwargs["client_certificate_path"] = cert_path
    if auth.client_certificate_password:
        kwargs["client_certificate_password"] = auth.client_certificate_password
    return kwargs


def manifest_profile_overrides(
    *, aws_profile: str = "", azure_auth: AzureAuthOptions | None = None, subscription_id: str | None = None
) -> list[str]:
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
