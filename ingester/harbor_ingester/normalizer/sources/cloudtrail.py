"""CloudTrail + STS normalizers.

CloudTrail's LookupEvents wraps the real record as a JSON string in ``CloudTrailEvent``; the
rich fields (userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters) live
there. We parse it, map to the unified schema, classify the user-agent, and flag a curated
set of sensitive actions so the console's CloudTrail Analyzer can surface them.
"""

from __future__ import annotations

import json
from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

# Actions that deserve attention in any investigation. Mapped to a category + severity bump.
SENSITIVE_ACTIONS: dict[str, tuple[str, str]] = {
    # IAM / credential
    "CreateUser": ("iam", "high"),
    "CreateAccessKey": ("iam", "high"),
    "CreateLoginProfile": ("iam", "high"),
    "UpdateLoginProfile": ("iam", "high"),
    "AttachUserPolicy": ("iam", "high"),
    "AttachRolePolicy": ("iam", "high"),
    "PutUserPolicy": ("iam", "high"),
    "PutRolePolicy": ("iam", "high"),
    "CreateRole": ("iam", "medium"),
    "UpdateAssumeRolePolicy": ("iam", "high"),
    "DeactivateMFADevice": ("iam", "high"),
    "DeleteVirtualMFADevice": ("iam", "high"),
    # Defense evasion
    "StopLogging": ("configuration", "critical"),
    "DeleteTrail": ("configuration", "critical"),
    "UpdateTrail": ("configuration", "high"),
    "PutEventSelectors": ("configuration", "high"),
    "DeleteFlowLogs": ("configuration", "high"),
    "DeleteDetector": ("threat", "critical"),
    "DisassociateFromMasterAccount": ("threat", "high"),
    "DeleteConfigurationRecorder": ("configuration", "high"),
    "StopConfigurationRecorder": ("configuration", "high"),
    # Data / exfil
    "PutBucketPolicy": ("data", "high"),
    "PutBucketAcl": ("data", "high"),
    "DeleteBucketPolicy": ("data", "medium"),
    "ModifySnapshotAttribute": ("data", "high"),
    "SharedSnapshotCopyInitiated": ("data", "high"),
    "PutBucketPublicAccessBlock": ("data", "medium"),
    "GetObject": ("data", "info"),
    # Credential access
    "GetSecretValue": ("iam", "medium"),
    "Decrypt": ("iam", "info"),
    "GetParameter": ("iam", "info"),
    # Persistence / compute
    "RunInstances": ("configuration", "medium"),
    "CreateFunction": ("configuration", "medium"),
    "UpdateFunctionCode": ("configuration", "high"),
}

USER_TYPE_MAP = {
    "IAMUser": "IAMUser",
    "AssumedRole": "AssumedRole",
    "Root": "Root",
    "FederatedUser": "FederatedUser",
    "AWSService": "AWSService",
    "AWSAccount": "AWSService",
}


def classify_user_agent(ua: str) -> str:
    if not ua:
        return "unknown"
    low = ua.lower()
    if "console" in low or "signin.amazonaws.com" in low:
        return "console"
    if "aws-cli" in low:
        return "cli"
    if any(s in low for s in ("boto", "aws-sdk", "botocore", "terraform", "pulumi")):
        return "sdk"
    if low.endswith(".amazonaws.com"):
        return "service"
    return "unknown"


def _unwrap(record: dict[str, Any]) -> dict[str, Any]:
    """Return the inner CloudTrail record (parsing CloudTrailEvent when present)."""
    inner = record.get("CloudTrailEvent")
    if isinstance(inner, str):
        try:
            detail = json.loads(inner)
            detail["_harbor_region"] = record.get("_harbor_region", detail.get("awsRegion", ""))
            return detail
        except json.JSONDecodeError:
            pass
    return record


def _principal(detail: dict[str, Any]) -> tuple[str, str, str, str]:
    ui = detail.get("userIdentity", {}) or {}
    utype = USER_TYPE_MAP.get(ui.get("type", ""), "Unknown")
    arn = ui.get("arn", "")
    uid = ui.get("principalId", "")
    name = (
        ui.get("userName")
        or (ui.get("sessionContext", {}).get("sessionIssuer", {}) or {}).get("userName")
        or (arn.split("/")[-1] if arn else "")
        or ui.get("type", "")
    )
    return name, uid, arn, utype


def _to_event(detail: dict[str, Any], ctx: NormalizeContext) -> UnifiedEvent:
    action = detail.get("eventName", "")
    name, uid, arn, utype = _principal(detail)
    ua = detail.get("userAgent", "")
    err = detail.get("errorCode", "")
    outcome = "failure" if err else "success"

    category = "iam" if detail.get("eventSource") == "iam.amazonaws.com" else "authentication"
    severity = "info"
    if action in SENSITIVE_ACTIONS:
        category, severity = SENSITIVE_ACTIONS[action]
    if action == "ConsoleLogin":
        category = "authentication"
        if (detail.get("responseElements", {}) or {}).get("ConsoleLogin") == "Failure":
            outcome = "failure"
            severity = "medium"
    if err in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"):
        severity = "low" if severity == "info" else severity

    src_ip = detail.get("sourceIPAddress", "")
    # Console / SDK calls report a service hostname here rather than an IP — keep it but don't
    # treat it as a network IP for pivots.
    is_ip = src_ip and not src_ip.endswith(".amazonaws.com")

    resources = detail.get("resources", []) or []
    res_arn = resources[0].get("ARN", "") if resources else ""
    res_type = resources[0].get("type", "") if resources else ""

    related_users = [u for u in {name, arn} if u]
    related_res = [r.get("ARN", "") for r in resources if r.get("ARN")]

    ev = UnifiedEvent(
        timestamp=detail.get("eventTime", ""),
        event_kind="event",
        event_category=[category],
        event_action=action,
        event_outcome=outcome,
        event_severity=severity,
        event_provider="cloudtrail",
        cloud_account=detail.get("recipientAccountId", ctx.account_id),
        cloud_region=detail.get("awsRegion", detail.get("_harbor_region", "")),
        cloud_service=detail.get("eventSource", "").split(".")[0],
        user_name=name,
        user_id=uid,
        user_arn=arn,
        user_type=utype,
        source_ip=src_ip if is_ip else "",
        ua_original=ua,
        ua_category=classify_user_agent(ua),
        resource_type=res_type,
        resource_id=res_arn.split("/")[-1] if res_arn else "",
        resource_arn=res_arn,
        related_ip=[src_ip] if is_ip else [],
        related_user=related_users,
        related_resource=related_res,
        message=_message(action, name, err, detail.get("eventSource", "")),
        case_id=ctx.case_id,
        harbor_source="cloudtrail",
        raw=detail,
    )
    return ev


def _message(action: str, who: str, err: str, service: str) -> str:
    base = f"{who or 'unknown'} called {action} ({service})"
    return f"{base} — DENIED ({err})" if err else base


@register("cloudtrail")
def normalize_cloudtrail(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        detail = _unwrap(rec)
        if not detail.get("eventTime"):
            continue
        yield _to_event(detail, ctx)


@register("sts")
def normalize_sts(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    """STS records are CloudTrail AssumeRole events; reuse the same mapping but force the
    session category so the Identity panel's role-assumption graph can select them."""
    for rec in records:
        detail = _unwrap(rec)
        if not detail.get("eventTime"):
            continue
        ev = _to_event(detail, ctx)
        ev.event_category = ["session", "authentication"]
        ev.harbor_source = "sts"
        # The graph edge targets the *role* (stable), not the per-session assumed-role ARN.
        req = detail.get("requestParameters", {}) or {}
        resp = detail.get("responseElements", {}) or {}
        role_arn = req.get("roleArn", "")
        assumed = (resp.get("assumedRoleUser", {}) or {}).get("arn", "")
        if role_arn:
            ev.resource_arn = role_arn
            ev.resource_type = "iam-role"
            ev.resource_id = role_arn.split("/")[-1]
        ev.related_resource = sorted({r for r in (role_arn, assumed) if r})
        yield ev
