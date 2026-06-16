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


@register("activity_log")
def normalize_activity_log(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        op = rec.get("operationName") or {}
        if isinstance(op, dict):
            op_name = op.get("value") or op.get("localizedValue") or ""
        else:
            op_name = str(op)
        status = rec.get("status") or {}
        if isinstance(status, dict):
            status_val = status.get("value") or status.get("localizedValue") or "Succeeded"
        else:
            status_val = str(status)
        caller = rec.get("caller") or rec.get("claims", {}).get("name", "")
        ip = rec.get("callerIpAddress") or ""
        resource_id = rec.get("resourceId") or rec.get("resource_id") or ""
        sub = rec.get("subscriptionId") or ctx.account_id
        region = ""
        rid = resource_id.lower()
        if "/locations/" in rid:
            region = rid.split("/locations/")[1].split("/")[0]
        outcome = "failure" if "fail" in status_val.lower() else "success"
        yield UnifiedEvent(
            timestamp=rec.get("eventTimestamp") or rec.get("submissionTimestamp") or "",
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
            message=f"{op_name} on {resource_id or 'subscription'}",
            case_id=ctx.case_id,
            ventra_source="activity_log",
            raw=rec,
        )
