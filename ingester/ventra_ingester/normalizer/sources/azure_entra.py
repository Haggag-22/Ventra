"""Entra ID sign-in and audit logs → unified events."""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register


def _signin_outcome(status: dict[str, Any] | None) -> str:
    if not status:
        return "unknown"
    code = (status.get("errorCode") or 0)
    try:
        return "failure" if int(code) != 0 else "success"
    except (TypeError, ValueError):
        return "unknown"


@register("entra_signin")
def normalize_entra_signin(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        user = rec.get("userPrincipalName") or rec.get("userDisplayName") or ""
        ip = rec.get("ipAddress") or ""
        app = rec.get("appDisplayName") or rec.get("resourceDisplayName") or ""
        outcome = _signin_outcome(rec.get("status"))
        yield UnifiedEvent(
            timestamp=rec.get("createdDateTime") or "",
            event_kind="event",
            event_category=["identity", "authentication"],
            event_action=rec.get("signInEventType") or "signIn",
            event_outcome=outcome,
            event_severity="medium" if outcome == "failure" else "info",
            event_provider="entra",
            cloud_provider="azure",
            cloud_account=ctx.account_id,
            cloud_service="entra",
            user_name=user,
            user_id=rec.get("userId") or "",
            source_ip=ip,
            source_country=(rec.get("location") or {}).get("countryOrRegion", ""),
            related_ip=[ip] if ip else [],
            related_user=[user] if user else [],
            message=f"Sign-in: {user} → {app}" if app else f"Sign-in: {user}",
            case_id=ctx.case_id,
            ventra_source="entra_signin",
            raw=rec,
        )


@register("entra_audit")
def normalize_entra_audit(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        initiator = rec.get("initiatedBy") or {}
        user = ""
        if isinstance(initiator, dict):
            user_obj = initiator.get("user") or {}
            app_obj = initiator.get("app") or {}
            user = user_obj.get("userPrincipalName") or user_obj.get("displayName") or ""
            if not user:
                user = app_obj.get("displayName") or app_obj.get("appId") or ""
        target = (rec.get("targetResources") or [{}])[0]
        target_name = target.get("displayName") or target.get("id") or ""
        action = rec.get("activityDisplayName") or rec.get("operationType") or "audit"
        yield UnifiedEvent(
            timestamp=rec.get("activityDateTime") or "",
            event_kind="event",
            event_category=["identity", "directory"],
            event_action=action,
            event_outcome="success",
            event_severity="medium",
            event_provider="entra",
            cloud_provider="azure",
            cloud_account=ctx.account_id,
            cloud_service="entra",
            user_name=user,
            resource_id=target_name,
            related_user=[user] if user else [],
            related_resource=[target_name] if target_name else [],
            message=f"{action}: {target_name}" if target_name else action,
            case_id=ctx.case_id,
            ventra_source="entra_audit",
            raw=rec,
        )
