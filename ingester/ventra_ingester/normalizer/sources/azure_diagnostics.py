"""Azure diagnostic log normalizers (Storage-routed resource logs).

Collectors ship raw Azure Monitor diagnostic JSON records; field names vary by category.
These normalizers extract the common forensic fields (timestamp, client IP, action, resource)
into UnifiedEvent rows for the Web, DNS, data-access, and Kubernetes panels.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register


def _props(rec: dict[str, Any]) -> dict[str, Any]:
    p = rec.get("properties")
    return p if isinstance(p, dict) else rec


def _ts(rec: dict[str, Any]) -> str:
    return str(rec.get("time") or rec.get("TimeGenerated") or _props(rec).get("time") or "")


def _resource_id(rec: dict[str, Any]) -> str:
    return str(rec.get("resourceId") or rec.get("_ventra_resource_id") or "")


def _diag_event(
    rec: dict[str, Any],
    ctx: NormalizeContext,
    *,
    source: str,
    service: str,
    category: list[str],
    action: str,
    message: str,
    source_ip: str = "",
    user_name: str = "",
    severity: str = "info",
    outcome: str = "unknown",
    event_kind: str = "event",
) -> UnifiedEvent:
    rid = _resource_id(rec)
    return UnifiedEvent(
        timestamp=_ts(rec),
        event_kind=event_kind,
        event_category=category,
        event_action=action,
        event_outcome=outcome,
        event_severity=severity,
        event_provider=source,
        cloud_provider="azure",
        cloud_account=ctx.account_id,
        cloud_service=service,
        user_name=user_name,
        source_ip=source_ip,
        resource_id=rid,
        resource_arn=rid,
        related_ip=[source_ip] if source_ip else [],
        related_user=[user_name] if user_name else [],
        related_resource=[rid] if rid else [],
        message=message,
        case_id=ctx.case_id,
        ventra_source=source,
        raw=rec,
    )


def _normalize_web(rec: dict, ctx: NormalizeContext, source: str, service: str) -> UnifiedEvent:
    p = _props(rec)
    ip = str(p.get("clientIP") or p.get("clientIp") or p.get("clientIpAddress") or "")
    method = str(p.get("httpMethod") or p.get("requestMethod") or "")
    uri = str(p.get("requestUri") or p.get("originalRequestUriWithArgs") or p.get("uri") or "")
    status = str(p.get("httpStatus") or p.get("statusCode") or "")
    action = str(p.get("action") or rec.get("category") or "request")
    blocked = action.upper() in {"BLOCK", "BLOCKED", "DENY", "REJECT"}
    outcome = "failure" if blocked or (status.isdigit() and int(status) >= 400) else "success"
    severity = "medium" if blocked else "info"
    msg = f"{method} {uri}".strip() or action
    if ip:
        msg = f"{ip} {msg}"
    return _diag_event(
        rec, ctx, source=source, service=service, category=["web"],
        action=action, message=msg, source_ip=ip, severity=severity, outcome=outcome,
    )


def _normalize_dns(rec: dict, ctx: NormalizeContext) -> UnifiedEvent:
    p = _props(rec)
    qname = str(p.get("QueryName") or p.get("queryName") or p.get("query_name") or "")
    rcode = str(p.get("ResponseCode") or p.get("responseCode") or p.get("rcode") or "")
    src = str(p.get("SourceIp") or p.get("clientIP") or "")
    outcome = "failure" if rcode.upper() in {"NXDOMAIN", "SERVFAIL", "REFUSED"} else "success"
    return _diag_event(
        rec, ctx, source="dns", service="dns", category=["network"],
        action=f"dns-query:{p.get('QueryType', p.get('queryType', ''))}",
        message=f"{qname} → {rcode}" if qname else "DNS query",
        source_ip=src, outcome=outcome,
    )


def _normalize_storage(rec: dict, ctx: NormalizeContext) -> UnifiedEvent:
    p = _props(rec)
    op = str(p.get("operationName") or rec.get("category") or "storage")
    uri = str(p.get("uri") or p.get("requestUri") or "")
    caller = str(p.get("callerIpAddress") or p.get("clientIp") or "")
    auth = str(p.get("authenticationType") or p.get("identity", {}).get("type", ""))
    status = str(p.get("statusCode") or p.get("statusText") or "")
    outcome = "failure" if status.startswith(("4", "5")) else "success"
    return _diag_event(
        rec, ctx, source="storage_access", service="storage", category=["data"],
        action=op, message=f"{op} {uri}".strip() or op,
        source_ip=caller, user_name=auth, outcome=outcome,
    )


def _normalize_key_vault(rec: dict, ctx: NormalizeContext) -> UnifiedEvent:
    p = _props(rec)
    op = str(p.get("operationName") or "AuditEvent")
    caller = str(p.get("callerIpAddress") or p.get("clientIp") or "")
    identity = str(p.get("identity", {}).get("claim", {}).get("upn", "") if isinstance(p.get("identity"), dict) else "")
    result = str(p.get("resultSignature") or p.get("resultType") or "")
    outcome = "failure" if result.lower() in {"unauthorized", "failure"} else "success"
    return _diag_event(
        rec, ctx, source="key_vault", service="keyvault", category=["data"],
        action=op, message=f"Key Vault {op}" + (f" by {identity}" if identity else ""),
        source_ip=caller, user_name=identity, outcome=outcome,
    )


@register("azure_firewall")
def normalize_azure_firewall(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        p = _props(rec)
        msg = str(p.get("msg") or rec.get("category") or "firewall")
        src = str(p.get("srcIp") or p.get("sourceIp") or "")
        dst = str(p.get("destIp") or p.get("destinationIp") or "")
        action = str(p.get("action") or "flow")
        yield _diag_event(
            rec, ctx, source="azure_firewall", service="firewall", category=["network"],
            action=action, message=f"{src} → {dst}: {msg}" if src else msg,
            source_ip=src, outcome="failure" if action.lower() == "deny" else "success",
        )


@register("app_gateway")
def normalize_app_gateway(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        cat = str(rec.get("category") or "")
        if "Firewall" in cat:
            yield _normalize_web(rec, ctx, "app_gateway", "appgateway")
        else:
            yield _normalize_web(rec, ctx, "app_gateway", "appgateway")


@register("front_door")
def normalize_front_door(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        yield _normalize_web(rec, ctx, "front_door", "frontdoor")


@register("dns")
def normalize_dns(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        yield _normalize_dns(rec, ctx)


@register("storage_access")
def normalize_storage_access(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        yield _normalize_storage(rec, ctx)


@register("key_vault")
def normalize_key_vault(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        yield _normalize_key_vault(rec, ctx)


@register("aks_audit")
def normalize_aks_audit(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    """Reuse the EKS audit shape — kube-audit JSON is the same format."""
    from .eks_audit import normalize_eks_audit

    tagged = []
    for rec in records:
        if rec.get("_ventra_cluster") and not rec.get("_ventra_region"):
            rec = {**rec, "_ventra_region": ""}
        tagged.append(rec)
    for ev in normalize_eks_audit(tagged, ctx):
        ev.ventra_source = "aks_audit"
        ev.event_provider = "aks_audit"
        ev.cloud_service = "aks"
        yield ev
