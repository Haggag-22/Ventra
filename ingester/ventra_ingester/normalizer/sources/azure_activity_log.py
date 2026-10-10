"""Azure Activity Log → unified events."""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register


def _severity(operation: str, status: str) -> str:
    op = (operation or "").lower()
    if "delete" in op or "purge" in op:
        return "high"
    if status.lower() in ("failed", "failure"):
        return "medium"
    return "info"


def _named(value: Any) -> tuple[str, str]:
    """Return ``(machine value, localized label)`` for an Azure SDK name object.

    The management SDK serializes these as snake_case dicts (``operation_name.value``);
    the REST payload uses camelCase (``operationName.value``). A plain string is both.
    """
    if isinstance(value, dict):
        machine = str(value.get("value") or value.get("localizedValue") or value.get("localized_value") or "")
        label = str(value.get("localizedValue") or value.get("localized_value") or machine)
        return machine, label
    text = str(value or "")
    return text, text


@register("activity_log")
def normalize_activity_log(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        identity = rec.get("identity") if isinstance(rec.get("identity"), dict) else {}
        op_name, op_label = _named(rec.get("operationName") or rec.get("operation_name") or {})
        if not op_name:
            auth = rec.get("authorization") or identity.get("authorization") or {}
            if isinstance(auth, dict):
                op_name = str(auth.get("action") or "")
                op_label = op_label or op_name
        status_val, _ = _named(rec.get("status") or {})
        if not status_val:
            status_val = str(rec.get("resultType") or rec.get("resultSignature") or "Succeeded")
        claims = rec.get("claims") if isinstance(rec.get("claims"), dict) else {}
        if not claims and isinstance(identity.get("claims"), dict):
            claims = identity["claims"]
        caller = str(rec.get("caller") or claims.get("name") or "")
        ip = str(rec.get("callerIpAddress") or rec.get("caller_ip_address") or claims.get("ipaddr") or "")
        resource_id = str(rec.get("resourceId") or rec.get("resource_id") or "")
        sub = str(rec.get("subscriptionId") or rec.get("subscription_id") or ctx.account_id)
        region = ""
        rid = resource_id.lower()
        if "/locations/" in rid:
            region = rid.split("/locations/")[1].split("/")[0]
        outcome = "failure" if "fail" in status_val.lower() else "success"
        label = op_label or op_name
        yield UnifiedEvent(
            timestamp=str(
                rec.get("eventTimestamp")
                or rec.get("event_timestamp")
                or rec.get("time")
                or rec.get("submissionTimestamp")
                or rec.get("submission_timestamp")
                or ""
            ),
            event_kind="event",
            event_category=["control_plane"],
            event_action=op_name,
            event_outcome=outcome,
            event_severity=_severity(op_name, status_val),
            event_provider="activity_log",
            cloud_provider="azure",
            cloud_account=sub,
            cloud_region=region,
            cloud_service="azure",
            user_name=caller,
            source_ip=ip,
            resource_id=resource_id,
            resource_arn=resource_id,
            related_ip=[ip] if ip else [],
            related_user=[caller] if caller else [],
            related_resource=[resource_id] if resource_id else [],
            message=f"{label} on {resource_id or 'subscription'}",
            case_id=ctx.case_id,
            ventra_source="activity_log",
            raw=rec,
        )
