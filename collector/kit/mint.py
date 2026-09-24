"""Mint short-lived, scoped provider credentials for embedding in a ``.kit`` file."""

from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .format import format_iso, utcnow

# Default kit / credential lifetime when the provider does not return its own expiry.
DEFAULT_KIT_TTL_SECONDS = int(os.environ.get("VENTRA_KIT_TTL_SECONDS", str(4 * 3600)))
# AWS STS GetSessionToken / AssumeRole duration (capped by IAM policy; 1h–12h typical).
DEFAULT_AWS_DURATION_SECONDS = int(os.environ.get("VENTRA_KIT_AWS_DURATION_SECONDS", str(3600)))


@dataclass
class MintedCredential:
    """Material written under ``credentials/`` plus kit.json credential metadata."""

    provider: str
    kind: str
    expires_at: datetime
    files: dict[str, str] = field(default_factory=dict)  # relative path -> text content
    acquisition_fields: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def meta_dict(self) -> dict[str, Any]:
        primary = next(iter(self.files), "")
        out: dict[str, Any] = {
            "provider": self.provider,
            "kind": self.kind,
            "expires_at": format_iso(self.expires_at),
            "path": primary,
        }
        out.update(self.details)
        return out


def kit_ttl_seconds() -> int:
    return max(300, DEFAULT_KIT_TTL_SECONDS)


def mint_connection_credentials(conn: dict[str, Any], *, cloud: str) -> MintedCredential:
    """Produce embeddable short-lived credentials from a saved Authentication connection."""
    platform = (conn.get("platform") or cloud or "").strip().lower()
    if platform == "aws":
        return _mint_aws(conn)
    if platform == "gcp":
        return _mint_gcp(conn)
    if platform in ("azure", "m365"):
        return _mint_azure(conn)
    if platform == "kubernetes":
        return _mint_kubernetes(conn)
    raise ValueError(f"unsupported platform for kit credentials: {platform!r}")


def _ttl_expiry() -> datetime:
    return utcnow() + timedelta(seconds=kit_ttl_seconds())


def _mint_aws(conn: dict[str, Any]) -> MintedCredential:
    import boto3

    auth_method = (conn.get("auth_method") or "").strip().lower()
    access_key = (conn.get("aws_access_key_id") or "").strip()
    secret_key = (conn.get("aws_secret_access_key") or "").strip()
    session_token = (conn.get("aws_session_token") or "").strip()
    profile = (conn.get("profile_name") or "").strip() or None
    role_arn = (conn.get("role_arn") or "").strip()
    duration = max(900, min(DEFAULT_AWS_DURATION_SECONDS, 43200))

    # Profile-only without keys: prefer resolving into STS; if unavailable, stamp TTL on the profile.
    if auth_method in ("profile", "default") and not access_key and not role_arn:
        if not profile and auth_method == "profile":
            raise ValueError("AWS profile connection is missing profile_name.")
        try:
            base = boto3.Session(profile_name=profile) if profile else boto3.Session()
            return _aws_sts_from_session(
                base,
                role_arn="",
                duration=duration,
                session_name=f"ventra-kit-{uuid.uuid4().hex[:10]}",
                extra_fields={"aws_profile": profile} if profile else {},
            )
        except Exception as exc:  # noqa: BLE001
            fields: dict[str, Any] = {"auth_method": auth_method or "profile"}
            if profile:
                fields["aws_profile"] = profile
            return MintedCredential(
                provider="aws",
                kind="profile_ttl",
                expires_at=_ttl_expiry(),
                files={},
                acquisition_fields=fields,
                details={"ttl_seconds": kit_ttl_seconds(), "mint_error": str(exc)},
            )

    if auth_method == "credentials" and access_key and secret_key:
        session_kwargs: dict[str, str] = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
        }
        if session_token:
            session_kwargs["aws_session_token"] = session_token
        base = boto3.Session(**session_kwargs)
    elif profile:
        base = boto3.Session(profile_name=profile)
    else:
        base = boto3.Session()

    session_name = f"ventra-kit-{uuid.uuid4().hex[:10]}"
    try:
        return _aws_sts_from_session(
            base,
            role_arn=role_arn if (role_arn or auth_method == "assume_role") else "",
            duration=duration,
            session_name=session_name,
            existing_session_token=session_token,
        )
    except Exception as exc:  # noqa: BLE001
        return _aws_static_fallback(conn, base, error=str(exc))


def _aws_sts_from_session(
    base: Any,
    *,
    role_arn: str,
    duration: int,
    session_name: str,
    existing_session_token: str = "",
    extra_fields: dict[str, Any] | None = None,
) -> MintedCredential:
    sts = base.client("sts")
    if role_arn:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration,
        )
        kind = "sts_assume_role"
    elif existing_session_token:
        frozen = base.get_credentials()
        if frozen is None:
            raise ValueError("AWS session credentials could not be resolved.")
        payload = {
            "aws_access_key_id": frozen.access_key,
            "aws_secret_access_key": frozen.secret_key,
            "aws_session_token": frozen.token or existing_session_token,
        }
        fields: dict[str, Any] = {
            "aws_credentials": "credentials/aws.json",
            "auth_method": "credentials",
        }
        if extra_fields:
            fields.update(extra_fields)
        return MintedCredential(
            provider="aws",
            kind="sts_session",
            expires_at=_ttl_expiry(),
            files={"credentials/aws.json": json.dumps(payload, indent=2) + "\n"},
            acquisition_fields=fields,
            details={"duration_seconds": duration, "reused_session": True},
        )
    else:
        resp = sts.get_session_token(DurationSeconds=duration)
        kind = "sts_session"

    creds = resp["Credentials"]
    expiry = creds["Expiration"]
    if isinstance(expiry, datetime):
        expires_at = expiry if expiry.tzinfo else expiry.replace(tzinfo=timezone.utc)
    else:
        expires_at = _ttl_expiry()

    payload = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    fields = {
        "aws_credentials": "credentials/aws.json",
        "auth_method": "credentials",
    }
    if role_arn:
        fields["aws_role_arn"] = role_arn
    if extra_fields:
        fields.update(extra_fields)

    return MintedCredential(
        provider="aws",
        kind=kind,
        expires_at=expires_at.astimezone(timezone.utc),
        files={"credentials/aws.json": json.dumps(payload, indent=2) + "\n"},
        acquisition_fields=fields,
        details={"duration_seconds": duration, "role_session_name": session_name},
    )


def _aws_static_fallback(conn: dict[str, Any], session: Any, *, error: str) -> MintedCredential:
    frozen = session.get_credentials()
    if frozen is None:
        raise ValueError(f"Could not mint AWS STS credentials ({error}) and no fallback credentials.")
    payload = {
        "aws_access_key_id": frozen.access_key,
        "aws_secret_access_key": frozen.secret_key,
    }
    if frozen.token:
        payload["aws_session_token"] = frozen.token
    fields: dict[str, Any] = {
        "aws_credentials": "credentials/aws.json",
        "auth_method": "credentials",
    }
    role_arn = (conn.get("role_arn") or "").strip()
    if role_arn:
        fields["aws_role_arn"] = role_arn
    return MintedCredential(
        provider="aws",
        kind="static_ttl",
        expires_at=_ttl_expiry(),
        files={"credentials/aws.json": json.dumps(payload, indent=2) + "\n"},
        acquisition_fields=fields,
        details={"mint_error": error, "ttl_seconds": kit_ttl_seconds()},
    )


def _mint_gcp(conn: dict[str, Any]) -> MintedCredential:
    auth_method = (conn.get("auth_method") or "").strip().lower()
    project = (conn.get("project") or "").strip()
    expires_at = _ttl_expiry()
    fields: dict[str, Any] = {"auth_method": auth_method or "service_account"}
    if project:
        fields["project"] = project

    if auth_method == "adc":
        return MintedCredential(
            provider="gcp",
            kind="adc_ttl",
            expires_at=expires_at,
            files={},
            acquisition_fields=fields,
            details={"ttl_seconds": kit_ttl_seconds(), "note": "Uses ADC on the run host until kit expiry."},
        )

    raw = (conn.get("gcp_service_account_json") or "").strip()
    if not raw:
        raise ValueError("GCP connection has no service account JSON to embed in the kit.")
    try:
        sa = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("GCP connection service account JSON is invalid.") from exc
    if not isinstance(sa, dict):
        raise ValueError("GCP connection service account JSON must be an object.")

    files = {"credentials/gcp-sa.json": json.dumps(sa, indent=2) + "\n"}
    fields["gcp_credentials"] = "credentials/gcp-sa.json"
    kind = "service_account_ttl"
    details: dict[str, Any] = {"ttl_seconds": kit_ttl_seconds()}

    # Best-effort short-lived access token (fails closed to SA JSON + kit TTL).
    try:
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_info(
            sa, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        from google.auth.transport.requests import Request

        creds.refresh(Request())
        if creds.token and creds.expiry:
            token_expiry = creds.expiry
            if token_expiry.tzinfo is None:
                token_expiry = token_expiry.replace(tzinfo=timezone.utc)
            token_payload = {
                "type": "authorized_user",
                "token": creds.token,
                "expiry": format_iso(token_expiry),
                "project_id": project or sa.get("project_id") or "",
                "client_email": sa.get("client_email") or "",
            }
            files["credentials/gcp-token.json"] = json.dumps(token_payload, indent=2) + "\n"
            fields["gcp_access_token"] = "credentials/gcp-token.json"
            kind = "access_token"
            expires_at = token_expiry.astimezone(timezone.utc)
            details["token_minted"] = True
    except Exception as exc:  # noqa: BLE001
        details["token_mint_error"] = str(exc)

    return MintedCredential(
        provider="gcp",
        kind=kind,
        expires_at=expires_at,
        files=files,
        acquisition_fields=fields,
        details=details,
    )


def _mint_azure(conn: dict[str, Any]) -> MintedCredential:
    tenant = (conn.get("azure_tenant_id") or "").strip()
    client = (conn.get("azure_client_id") or "").strip()
    subscription = (conn.get("subscription") or "").strip()
    secret = (conn.get("azure_client_secret") or "").strip()
    cert = (conn.get("azure_client_certificate_content") or "").strip()
    expires_at = _ttl_expiry()

    if not tenant or not client:
        raise ValueError("Azure connection needs azure_tenant_id and azure_client_id for kit embed.")
    if not secret and not cert:
        raise ValueError("Azure connection needs a client secret or certificate for kit embed.")

    payload: dict[str, str] = {
        "azure_tenant_id": tenant,
        "azure_client_id": client,
    }
    files: dict[str, str] = {}
    fields: dict[str, Any] = {
        "azure_tenant_id": tenant,
        "azure_client_id": client,
        "auth_method": (conn.get("auth_method") or "service_principal"),
    }
    if subscription:
        fields["subscription"] = subscription
    if secret:
        payload["azure_client_secret"] = secret
    if cert:
        files["credentials/azure-cert.pem"] = cert if cert.endswith("\n") else cert + "\n"
        payload["azure_client_certificate_path"] = "credentials/azure-cert.pem"
        fields["azure_client_certificate"] = "credentials/azure-cert.pem"

    files["credentials/azure.json"] = json.dumps(payload, indent=2) + "\n"
    fields["azure_credentials"] = "credentials/azure.json"
    details: dict[str, Any] = {"ttl_seconds": kit_ttl_seconds()}

    # Best-effort ARM token mint for an earlier natural expiry.
    if secret:
        try:
            from azure.identity import ClientSecretCredential

            cred = ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=secret)
            token = cred.get_token("https://management.azure.com/.default")
            token_exp = datetime.fromtimestamp(token.expires_on, tz=timezone.utc)
            token_payload = {
                "access_token": token.token,
                "expires_on": token.expires_on,
                "expires_at": format_iso(token_exp),
                "tenant_id": tenant,
                "client_id": client,
            }
            files["credentials/azure-token.json"] = json.dumps(token_payload, indent=2) + "\n"
            fields["azure_access_token"] = "credentials/azure-token.json"
            expires_at = token_exp
            details["token_minted"] = True
            details["kind_note"] = "SP secret also embedded; kit refuses runs past expires_at."
        except Exception as exc:  # noqa: BLE001
            details["token_mint_error"] = str(exc)

    return MintedCredential(
        provider="azure",
        kind="service_principal_ttl" if "azure-token.json" not in files else "access_token",
        expires_at=expires_at,
        files=files,
        acquisition_fields=fields,
        details=details,
    )


def _mint_kubernetes(conn: dict[str, Any]) -> MintedCredential:
    context = (conn.get("k8s_context") or "").strip()
    raw = (conn.get("kubeconfig_content") or "").strip()
    if not raw:
        raise ValueError(
            "Kubernetes connection has no kubeconfig content. "
            "Edit the connection under Authentication and paste the kubeconfig before downloading the kit."
        )

    expires_at = _ttl_expiry()
    kind = "kubeconfig_ttl"
    details: dict[str, Any] = {"ttl_seconds": kit_ttl_seconds()}
    kubeconfig_out = raw if raw.endswith("\n") else raw + "\n"

    # Prefer a minimal kubeconfig with only the bearer token when we can extract one.
    try:
        import yaml

        doc = yaml.safe_load(raw)
        if isinstance(doc, dict):
            token, token_exp = _extract_k8s_token(doc, context)
            if token:
                if token_exp is not None and token_exp <= utcnow():
                    raise ValueError(
                        f"Kubernetes bearer token expired at {format_iso(token_exp)}. "
                        "Refresh the kubeconfig / ServiceAccount token in Authentication, then download a new kit."
                    )
                minimal = _minimal_kubeconfig(doc, context, token)
                kubeconfig_out = yaml.safe_dump(minimal, sort_keys=False)
                kind = "sa_bearer_token"
                if token_exp is not None:
                    # Cap kit lifetime at the earlier of JWT exp and configured TTL.
                    ttl_cap = _ttl_expiry()
                    expires_at = min(token_exp, ttl_cap)
                    details["token_exp_from_jwt"] = True
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001
        details["token_extract_error"] = str(exc)

    fields: dict[str, Any] = {
        "kubeconfig": "credentials/kubeconfig.yaml",
        "node_root": "/",
    }
    if context:
        fields["k8s_context"] = context

    return MintedCredential(
        provider="kubernetes",
        kind=kind,
        expires_at=expires_at,
        files={"credentials/kubeconfig.yaml": kubeconfig_out},
        acquisition_fields=fields,
        details=details,
    )


def _extract_k8s_token(doc: dict[str, Any], context_name: str) -> tuple[str, datetime | None]:
    contexts = {c.get("name"): c for c in (doc.get("contexts") or []) if isinstance(c, dict)}
    users = {u.get("name"): u for u in (doc.get("users") or []) if isinstance(u, dict)}
    current = context_name or str(doc.get("current-context") or "")
    ctx = contexts.get(current) or (next(iter(contexts.values())) if contexts else None)
    if not ctx:
        return "", None
    user_name = (ctx.get("context") or {}).get("user")
    user = users.get(user_name) or {}
    user_cfg = user.get("user") or {}
    token = str(user_cfg.get("token") or "").strip()
    if not token:
        return "", None
    return token, _jwt_expiry(token)


def _jwt_expiry(token: str) -> datetime | None:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")))
        exp = payload.get("exp")
        if not exp:
            return None
        return datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except Exception:
        return None


def _minimal_kubeconfig(doc: dict[str, Any], context_name: str, token: str) -> dict[str, Any]:
    contexts = {c.get("name"): c for c in (doc.get("contexts") or []) if isinstance(c, dict)}
    clusters = {c.get("name"): c for c in (doc.get("clusters") or []) if isinstance(c, dict)}
    current = context_name or str(doc.get("current-context") or "")
    ctx = contexts.get(current) or next(iter(contexts.values()))
    ctx_body = ctx.get("context") or {}
    cluster_name = ctx_body.get("cluster")
    cluster = clusters.get(cluster_name) or next(iter(clusters.values()), {})
    user_name = "ventra-kit"
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": ctx.get("name") or current or "ventra",
        "clusters": [cluster] if cluster else list(doc.get("clusters") or []),
        "contexts": [
            {
                "name": ctx.get("name") or current or "ventra",
                "context": {
                    "cluster": cluster_name,
                    "user": user_name,
                    **({"namespace": ctx_body["namespace"]} if ctx_body.get("namespace") else {}),
                },
            }
        ],
        "users": [{"name": user_name, "user": {"token": token}}],
    }


def write_minted_credentials(staging: Path, minted: MintedCredential) -> None:
    """Write credential files + ``credentials/meta.json`` into the kit staging tree."""
    for rel, content in minted.files.items():
        path = staging / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    meta_path = staging / "credentials" / "meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(minted.meta_dict(), indent=2) + "\n", encoding="utf-8")
