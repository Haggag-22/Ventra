"""Log Analytics diagnostic log normalizer — routes LA rows to panel-specific shapes."""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register
from . import azure_diagnostics as diag


def _as_diag_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Map flat LA rows into the nested shape Storage diagnostic collectors emit."""
    if rec.get("properties"):
        return rec
    props = {k: v for k, v in rec.items() if not k.startswith("_ventra")}
    # Log Analytics columns often use *_s / *_d suffixes.
    if "clientIP_s" in props and "clientIP" not in props:
        props["clientIP"] = props["clientIP_s"]
    if "clientIp_s" in props and "clientIP" not in props:
        props["clientIP"] = props["clientIp_s"]
    if "httpMethod_s" in props and "httpMethod" not in props:
        props["httpMethod"] = props["httpMethod_s"]
    if "requestUri_s" in props and "requestUri" not in props:
        props["requestUri"] = props["requestUri_s"]
    if "httpStatus_d" in props and "httpStatus" not in props:
        props["httpStatus"] = props["httpStatus_d"]
    if "action_s" in props and "action" not in props:
        props["action"] = props["action_s"]
    out = dict(rec)
    out["properties"] = props
    out.setdefault("time", rec.get("TimeGenerated") or rec.get("time"))
    out.setdefault("resourceId", rec.get("ResourceId") or rec.get("_ventra_resource_id"))
    out.setdefault("category", rec.get("Category") or rec.get("category"))
    return out


def _normalize_row(rec: dict[str, Any], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    shaped = _as_diag_record(rec)
    source = str(rec.get("_ventra_la_source") or "log_analytics")
    if source == "azure_firewall":
        yield from diag.normalize_azure_firewall([shaped], ctx)
    elif source == "app_gateway":
        yield from diag.normalize_app_gateway([shaped], ctx)
    elif source == "front_door":
        yield from diag.normalize_front_door([shaped], ctx)
    elif source == "dns":
        yield from diag.normalize_dns([shaped], ctx)
    elif source == "storage_access":
        yield from diag.normalize_storage_access([shaped], ctx)
    elif source == "key_vault":
        yield from diag.normalize_key_vault([shaped], ctx)
    elif source == "aks_audit":
        yield from diag.normalize_aks_audit([shaped], ctx)
    else:
        yield diag._diag_event(
            shaped,
            ctx,
            source="log_analytics",
            service="monitor",
            category=["data"],
            action=str(shaped.get("category") or "log_analytics"),
            message=str(shaped.get("OperationName") or shaped.get("category") or "Log Analytics row"),
        )


@register("log_analytics")
def normalize_log_analytics(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        yield from _normalize_row(rec, ctx)
