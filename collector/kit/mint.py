"""Mint short-lived, scoped provider credentials for embedding in a ``.kit`` file.

A kit is runnable until the earlier of the kit limit (``VENTRA_KIT_TTL_SECONDS``, default
7 days) and the embedded credential's own expiry. Each provider asks for the longest
lifetime its short-lived credentials allow; long-lived secrets are never used to stretch a
kit past what the short-lived credential can do.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .format import format_iso, human_duration, utcnow

DEFAULT_KIT_TTL_SECONDS = 7 * 24 * 3600
# Kits that can only carry a long-lived secret (no short-lived token could be minted) keep
# the previous short limit instead of inheriting the 7-day kit limit.
DEFAULT_STATIC_SECRET_TTL_SECONDS = 4 * 3600

# AWS hard limits: GetSessionToken (IAM user) ≤ 36h, AssumeRole ≤ the role's
# MaxSessionDuration (≤ 12h; 1h when role chaining). Longest first; AWS rejects too-long asks.
AWS_SESSION_TOKEN_MAX_SECONDS = 36 * 3600
AWS_ASSUME_ROLE_MAX_SECONDS = 12 * 3600
_AWS_SESSION_TOKEN_LADDER = (AWS_SESSION_TOKEN_MAX_SECONDS, 3600)
_AWS_ASSUME_ROLE_LADDER = (12 * 3600, 8 * 3600, 6 * 3600, 4 * 3600, 2 * 3600, 3600)

# GCP service-account access tokens: 1h by default, up to 12h when the org policy
# ``constraints/iam.allowServiceAccountCredentialLifetimeExtension`` lists the account.
GCP_TOKEN_MAX_SECONDS = 12 * 3600

LIMITED_BY_KIT = "kit"
LIMITED_BY_CREDENTIAL = "credential"
LIMITED_BY_STATIC_SECRET = "static_secret"

_CLOUD_TITLES = {"aws": "AWS", "gcp": "GCP", "azure": "Azure", "kubernetes": "Kubernetes"}


def _env_seconds(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def kit_ttl_seconds() -> int:
    return max(300, _env_seconds("VENTRA_KIT_TTL_SECONDS", DEFAULT_KIT_TTL_SECONDS))


def static_secret_ttl_seconds() -> int:
    return max(300, _env_seconds("VENTRA_KIT_STATIC_SECRET_TTL_SECONDS", DEFAULT_STATIC_SECRET_TTL_SECONDS))


def _aws_duration_ladder(ladder: tuple[int, ...], hard_max: int) -> list[int]:
    """Durations to try, longest first; ``VENTRA_KIT_AWS_DURATION_SECONDS`` caps the ask."""
    cap = min(_env_seconds("VENTRA_KIT_AWS_DURATION_SECONDS", hard_max), hard_max)
    cap = max(900, cap)
    out = [d for d in ladder if d <= cap]
    if cap not in out:
        out.insert(0, cap)
    return out


@dataclass
class MintedCredential:
    """Material written under ``credentials/`` plus kit.json credential metadata.

    ``expires_at`` is the credential's own expiry (``None`` when nothing expiring is embedded);
    :func:`mint_connection_credentials` clamps it to the kit limit and records which one won.
    """

    provider: str
    kind: str
    expires_at: datetime | None
    files: dict[str, str] = field(default_factory=dict)  # relative path -> text content
    acquisition_fields: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    lifetime_note: str = ""
    static_secret: bool = False

    def meta_dict(self) -> dict[str, Any]:
        primary = next(iter(self.files), "")
        out: dict[str, Any] = {
            "provider": self.provider,
            "kind": self.kind,
            "expires_at": format_iso(self.expires_at or _ttl_expiry()),
            "path": primary,
        }
        out.update(self.details)
        return out


def mint_connection_credentials(conn: dict[str, Any], *, cloud: str) -> MintedCredential:
    """Produce embeddable short-lived credentials from a saved Authentication connection."""
    platform = (conn.get("platform") or cloud or "").strip().lower()
    if platform == "aws":
        minted = _mint_aws(conn)
    elif platform == "gcp":
        minted = _mint_gcp(conn)
    elif platform == "azure":
        minted = _mint_azure(conn)
    elif platform == "kubernetes":
        minted = _mint_kubernetes(conn)
    else:
        raise ValueError(f"unsupported platform for kit credentials: {platform!r}")
    return _apply_kit_limit(minted)


def _apply_kit_limit(minted: MintedCredential) -> MintedCredential:
    """Clamp to the kit limit and record whether the kit or the credential sets the expiry."""
    kit_exp = _ttl_expiry()
    if minted.expires_at is None or minted.expires_at >= kit_exp:
        minted.expires_at = kit_exp
        limited_by = LIMITED_BY_KIT
    elif minted.static_secret:
        limited_by = LIMITED_BY_STATIC_SECRET
    else:
        limited_by = LIMITED_BY_CREDENTIAL
    minted.details["limited_by"] = limited_by
    minted.details["kit_ttl_seconds"] = kit_ttl_seconds()
    if minted.lifetime_note:
        minted.details["lifetime_note"] = minted.lifetime_note
    return minted


def _ttl_expiry() -> datetime:
    return utcnow() + timedelta(seconds=kit_ttl_seconds())


def _static_secret_expiry() -> datetime:
    return utcnow() + timedelta(seconds=static_secret_ttl_seconds())


def _static_note(cloud: str, secret: str) -> str:
    return (
        f"This kit carries a long-lived {_CLOUD_TITLES.get(cloud, cloud)} {secret} because no "
        f"short-lived credential could be minted, so it is limited to "
        f"{human_duration(static_secret_ttl_seconds())}."
    )


def _is_duration_rejection(exc: Exception) -> bool:
    """True when AWS refused the requested DurationSeconds (retry shorter)."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error") or {}
    return str(error.get("Code") or "") == "ValidationError"


def _mint_aws(conn: dict[str, Any]) -> MintedCredential:
    import boto3

    auth_method = (conn.get("auth_method") or "").strip().lower()
    access_key = (conn.get("aws_access_key_id") or "").strip()
    secret_key = (conn.get("aws_secret_access_key") or "").strip()
    session_token = (conn.get("aws_session_token") or "").strip()
    profile = (conn.get("profile_name") or "").strip() or None
    role_arn = (conn.get("role_arn") or "").strip()

    # Profile-only without keys: prefer resolving into STS; if unavailable, the run host's
    # profile is used and nothing is embedded.
    if auth_method in ("profile", "default") and not access_key and not role_arn:
        if not profile and auth_method == "profile":
            raise ValueError("AWS profile connection is missing profile_name.")
        try:
            base = boto3.Session(profile_name=profile) if profile else boto3.Session()
            return _aws_sts_from_session(
                base,
                role_arn="",
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
                expires_at=None,
                files={},
                acquisition_fields=fields,
                details={"mint_error": str(exc)},
                lifetime_note="No credential is embedded; the run host's AWS profile is used.",
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
            session_name=session_name,
            existing_session_token=session_token,
        )
    except Exception as exc:  # noqa: BLE001
        return _aws_static_fallback(conn, base, error=str(exc))


def _aws_call_longest(call: Any, ladder: list[int]) -> tuple[dict[str, Any], int]:
    """Call STS with the longest duration AWS accepts for this identity / role."""
    last: Exception | None = None
    for duration in ladder:
        try:
            return call(duration), duration
        except Exception as exc:  # noqa: BLE001
            if not _is_duration_rejection(exc):
                raise
            last = exc
    assert last is not None
    raise last


def _aws_sts_from_session(
    base: Any,
    *,
    role_arn: str,
    session_name: str,
    existing_session_token: str = "",
    extra_fields: dict[str, Any] | None = None,
) -> MintedCredential:
    sts = base.client("sts")
    if role_arn:
        resp, duration = _aws_call_longest(
            lambda d: sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=d),
            _aws_duration_ladder(_AWS_ASSUME_ROLE_LADDER, AWS_ASSUME_ROLE_MAX_SECONDS),
        )
        kind = "sts_assume_role"
        note = (
            f"AWS AssumeRole session ({human_duration(duration)}). AWS caps role sessions at the "
            "role's maximum session duration (at most 12 hours; 1 hour when chaining roles)."
        )
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
        # AWS does not report the expiry of pasted session credentials; 36h after issue is the
        # longest any of them can live, so now + 36h is a true upper bound.
        return MintedCredential(
            provider="aws",
            kind="sts_session",
            expires_at=utcnow() + timedelta(seconds=AWS_SESSION_TOKEN_MAX_SECONDS),
            files={"credentials/aws.json": json.dumps(payload, indent=2) + "\n"},
            acquisition_fields=fields,
            details={"reused_session": True, "expiry_is_upper_bound": True},
            lifetime_note=(
                "Reuses the connection's AWS session credentials. AWS does not report their "
                "expiry; they last at most 36 hours from when they were issued."
            ),
        )
    else:
        resp, duration = _aws_call_longest(
            lambda d: sts.get_session_token(DurationSeconds=d),
            _aws_duration_ladder(_AWS_SESSION_TOKEN_LADDER, AWS_SESSION_TOKEN_MAX_SECONDS),
        )
        kind = "sts_session"
        note = (
            f"AWS STS session ({human_duration(duration)}). AWS caps session tokens at "
            "36 hours (1 hour for the root user)."
        )

    creds = resp["Credentials"]
    expiry = creds["Expiration"]
    if isinstance(expiry, datetime):
        expires_at = expiry if expiry.tzinfo else expiry.replace(tzinfo=timezone.utc)
    else:
        expires_at = utcnow() + timedelta(seconds=duration)

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
        lifetime_note=note,
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
        expires_at=_static_secret_expiry(),
        files={"credentials/aws.json": json.dumps(payload, indent=2) + "\n"},
        acquisition_fields=fields,
        details={"mint_error": error},
        lifetime_note=_static_note("aws", "access key"),
        static_secret=True,
    )


def _gcp_mint_token(sa: dict[str, Any]) -> tuple[str, datetime, int | None]:
    """Mint the longest-lived access token the service account is allowed (12h, else 1h)."""
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    source = service_account.Credentials.from_service_account_info(sa, scopes=scopes)
    email = str(sa.get("client_email") or "").strip()
    if email:
        try:
            from google.auth import impersonated_credentials

            extended = impersonated_credentials.Credentials(
                source_credentials=source,
                target_principal=email,
                target_scopes=scopes,
                lifetime=GCP_TOKEN_MAX_SECONDS,
            )
            extended.refresh(Request())
            if extended.token and extended.expiry:
                return extended.token, extended.expiry, GCP_TOKEN_MAX_SECONDS
        except Exception:  # noqa: BLE001 — org policy or token-creator role not granted
            pass
    source.refresh(Request())
    if not source.token or not source.expiry:
        raise ValueError("Google did not return an access token.")
    return source.token, source.expiry, None


def _mint_gcp(conn: dict[str, Any]) -> MintedCredential:
    auth_method = (conn.get("auth_method") or "").strip().lower()
    project = (conn.get("project") or "").strip()
    fields: dict[str, Any] = {"auth_method": auth_method or "service_account"}
    if project:
        fields["project"] = project

    if auth_method == "adc":
        return MintedCredential(
            provider="gcp",
            kind="adc_ttl",
            expires_at=None,
            files={},
            acquisition_fields=fields,
            details={"note": "Uses ADC on the run host until kit expiry."},
            lifetime_note="No credential is embedded; the run host's gcloud ADC login is used.",
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
    details: dict[str, Any] = {}

    try:
        token, token_expiry, extended = _gcp_mint_token(sa)
    except Exception as exc:  # noqa: BLE001
        details["token_mint_error"] = str(exc)
        return MintedCredential(
            provider="gcp",
            kind="service_account_ttl",
            expires_at=_static_secret_expiry(),
            files=files,
            acquisition_fields=fields,
            details=details,
            lifetime_note=_static_note("gcp", "service account key"),
            static_secret=True,
        )

    if token_expiry.tzinfo is None:
        token_expiry = token_expiry.replace(tzinfo=timezone.utc)
    token_payload = {
        "type": "authorized_user",
        "token": token,
        "expiry": format_iso(token_expiry),
        "project_id": project or sa.get("project_id") or "",
        "client_email": sa.get("client_email") or "",
    }
    files["credentials/gcp-token.json"] = json.dumps(token_payload, indent=2) + "\n"
    fields["gcp_access_token"] = "credentials/gcp-token.json"
    details["token_minted"] = True
    if extended:
        details["token_lifetime_seconds"] = extended
        note = "GCP access token (12 hours, the maximum Google allows with lifetime extension)."
    else:
        note = (
            "GCP access token (1 hour). Google allows up to 12 hours only when the org policy "
            "iam.allowServiceAccountCredentialLifetimeExtension lists this service account."
        )
    return MintedCredential(
        provider="gcp",
        kind="access_token",
        expires_at=token_expiry.astimezone(timezone.utc),
        files=files,
        acquisition_fields=fields,
        details=details,
        lifetime_note=note,
    )


def _azure_mint_token(tenant: str, client: str, *, secret: str, cert: str) -> Any:
    scope = "https://management.azure.com/.default"
    if secret:
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=secret).get_token(
            scope
        )
    from azure.identity import CertificateCredential

    return CertificateCredential(
        tenant_id=tenant, client_id=client, certificate_data=cert.encode("utf-8")
    ).get_token(scope)


def _mint_azure(conn: dict[str, Any]) -> MintedCredential:
    tenant = (conn.get("azure_tenant_id") or "").strip()
    client = (conn.get("azure_client_id") or "").strip()
    subscription = (conn.get("subscription") or "").strip()
    secret = (conn.get("azure_client_secret") or "").strip()
    cert = (conn.get("azure_client_certificate_content") or "").strip()

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
    details: dict[str, Any] = {}

    try:
        token = _azure_mint_token(tenant, client, secret=secret, cert=cert)
    except Exception as exc:  # noqa: BLE001
        details["token_mint_error"] = str(exc)
        return MintedCredential(
            provider="azure",
            kind="service_principal_ttl",
            expires_at=_static_secret_expiry(),
            files=files,
            acquisition_fields=fields,
            details=details,
            lifetime_note=_static_note("azure", "client secret" if secret else "client certificate"),
            static_secret=True,
        )

    token_exp = datetime.fromtimestamp(token.expires_on, tz=timezone.utc)
    files["credentials/azure-token.json"] = (
        json.dumps(
            {
                "access_token": token.token,
                "expires_on": token.expires_on,
                "expires_at": format_iso(token_exp),
                "tenant_id": tenant,
                "client_id": client,
            },
            indent=2,
        )
        + "\n"
    )
    fields["azure_access_token"] = "credentials/azure-token.json"
    details["token_minted"] = True
    details["kind_note"] = "SP secret also embedded; kit refuses runs past expires_at."
    return MintedCredential(
        provider="azure",
        kind="access_token",
        expires_at=token_exp,
        files=files,
        acquisition_fields=fields,
        details=details,
        lifetime_note=(
            "Azure Resource Manager access token. Microsoft Entra ID issues these for "
            "60–90 minutes; Ventra cannot request longer."
        ),
    )


def _mint_kubernetes(conn: dict[str, Any]) -> MintedCredential:
    context = (conn.get("k8s_context") or "").strip()
    raw = (conn.get("kubeconfig_content") or "").strip()
    if not raw:
        raise ValueError(
            "Kubernetes connection has no kubeconfig content. "
            "Edit the connection under Authentication and paste the kubeconfig before downloading the kit."
        )

    expires_at: datetime | None = None
    kind = "kubeconfig_ttl"
    details: dict[str, Any] = {}
    note = "Embedded kubeconfig; the run host runs any auth plugin it names."
    static_secret = False
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
                    expires_at = token_exp
                    details["token_exp_from_jwt"] = True
                    note = (
                        "Kubernetes ServiceAccount token (expiry from the token). Issue one with "
                        "`kubectl create token <sa> --duration=168h` for a 7-day kit; some "
                        "clusters cap token lifetime lower."
                    )
                else:
                    expires_at = _static_secret_expiry()
                    static_secret = True
                    note = _static_note("kubernetes", "bearer token (no expiry)")
            elif _k8s_has_client_key(doc, context):
                expires_at = _static_secret_expiry()
                static_secret = True
                note = _static_note("kubernetes", "client certificate key")
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
        lifetime_note=note,
        static_secret=static_secret,
    )


def _k8s_user_cfg(doc: dict[str, Any], context_name: str) -> dict[str, Any]:
    contexts = {c.get("name"): c for c in (doc.get("contexts") or []) if isinstance(c, dict)}
    users = {u.get("name"): u for u in (doc.get("users") or []) if isinstance(u, dict)}
    current = context_name or str(doc.get("current-context") or "")
    ctx = contexts.get(current) or (next(iter(contexts.values())) if contexts else None)
    if not ctx:
        return {}
    user_name = (ctx.get("context") or {}).get("user")
    user = users.get(user_name) or {}
    return user.get("user") or {}


def _k8s_has_client_key(doc: dict[str, Any], context_name: str) -> bool:
    user_cfg = _k8s_user_cfg(doc, context_name)
    return bool(user_cfg.get("client-key-data") or user_cfg.get("client-key"))


def _extract_k8s_token(doc: dict[str, Any], context_name: str) -> tuple[str, datetime | None]:
    user_cfg = _k8s_user_cfg(doc, context_name)
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
