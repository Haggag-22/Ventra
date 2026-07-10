"""Embed saved connection authentication into an acquisition kit staging tree."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CREDENTIALS_DIR = "credentials"


def embed_connection_auth(staging: Path, conn: dict[str, Any], acq: dict[str, Any]) -> None:
    """Write non-interactive auth material into ``staging`` and annotate ``acq``."""
    platform = (conn.get("platform") or acq.get("cloud") or "").strip().lower()
    auth_method = (conn.get("auth_method") or "default").strip().lower() or "default"
    acq["auth_method"] = auth_method

    if platform == "aws":
        _embed_aws(staging, conn, acq, auth_method)
    elif platform == "gcp":
        _embed_gcp(staging, conn, acq, auth_method)
    elif platform in ("azure", "m365"):
        _embed_azure(staging, conn, acq, auth_method)


def _cred_dir(staging: Path) -> Path:
    path = staging / CREDENTIALS_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _embed_aws(staging: Path, conn: dict[str, Any], acq: dict[str, Any], auth_method: str) -> None:
    profile = (conn.get("profile_name") or "").strip()
    role_arn = (conn.get("role_arn") or "").strip()
    if role_arn:
        acq["aws_role_arn"] = role_arn

    access_key = (conn.get("aws_access_key_id") or "").strip()
    secret_key = (conn.get("aws_secret_access_key") or "").strip()
    if auth_method == "credentials" and access_key and secret_key:
        payload: dict[str, str] = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
        }
        token = (conn.get("aws_session_token") or "").strip()
        if token:
            payload["aws_session_token"] = token
        path = _cred_dir(staging) / "aws.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        acq["aws_credentials"] = f"{CREDENTIALS_DIR}/aws.json"
        return

    if profile:
        acq["aws_profile"] = profile


def _embed_gcp(staging: Path, conn: dict[str, Any], acq: dict[str, Any], auth_method: str) -> None:
    project = (conn.get("project") or "").strip()
    if project and not str(acq.get("project") or "").strip():
        acq["project"] = project

    if auth_method == "adc":
        return

    raw = (conn.get("gcp_service_account_json") or "").strip()
    if not raw:
        return
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("GCP connection service account JSON is invalid.") from exc
    if not isinstance(parsed, dict):
        raise ValueError("GCP connection service account JSON must be an object.")
    path = _cred_dir(staging) / "gcp-sa.json"
    path.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
    acq["gcp_credentials"] = f"{CREDENTIALS_DIR}/gcp-sa.json"


def _embed_azure(staging: Path, conn: dict[str, Any], acq: dict[str, Any], auth_method: str) -> None:
    tenant = (conn.get("azure_tenant_id") or "").strip()
    client = (conn.get("azure_client_id") or "").strip()
    subscription = (conn.get("subscription") or "").strip()
    if tenant:
        acq["azure_tenant_id"] = tenant
    if client:
        acq["azure_client_id"] = client
    if subscription and not str(acq.get("subscription") or "").strip():
        acq["subscription"] = subscription

    secret = (conn.get("azure_client_secret") or "").strip()
    cert = (conn.get("azure_client_certificate_content") or "").strip()
    if not secret and not cert:
        return

    payload: dict[str, str] = {}
    if tenant:
        payload["azure_tenant_id"] = tenant
    if client:
        payload["azure_client_id"] = client
    if secret:
        payload["azure_client_secret"] = secret
    if cert or auth_method == "certificate":
        payload["azure_client_certificate_content"] = cert
    path = _cred_dir(staging) / "azure.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    acq["azure_credentials"] = f"{CREDENTIALS_DIR}/azure.json"
