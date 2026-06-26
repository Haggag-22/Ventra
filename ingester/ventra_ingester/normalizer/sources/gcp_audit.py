"""GCP Cloud Audit Logs → unified events."""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

_AUDIT_SOURCES = frozenset(
    {
        "cloud_audit_admin",
        "cloud_audit_system",
        "cloud_audit_data",
        "login_events",
        "storage_access",
        "bigquery_audit",
        "cloud_sql",
        "secret_manager",
        "vm_logs",
        "cloud_functions",
        "api_gateway",
        "load_balancer",
        "firewall_logs",
        "cloud_monitoring",
    }
)


def _proto(rec: dict) -> dict[str, Any]:
    return rec.get("protoPayload") or {}


def _audit_event(rec: dict, ctx: NormalizeContext, source: str) -> UnifiedEvent:
    proto = _proto(rec)
    auth = proto.get("authenticationInfo") or {}
    req_meta = proto.get("requestMetadata") or {}
    resource = proto.get("resourceName") or rec.get("resource", {}).get("labels", {}).get(
        "project_id", ""
    )
    method = proto.get("methodName") or ""
    service = proto.get("serviceName") or ""
    principal = auth.get("principalEmail") or auth.get("principalSubject") or ""
    ip = req_meta.get("callerIp") or req_meta.get("callerSuppliedUserAgent", "")
    project = rec.get("_ventra_project_id") or ctx.account_id
    severity = (rec.get("severity") or "INFO").lower()
    sev_map = {"error": "high", "warning": "medium", "critical": "critical"}
    return UnifiedEvent(
        timestamp=rec.get("timestamp") or "",
        event_kind="event",
        event_category=["control_plane"],
        event_action=method or service,
        event_outcome="success",
        event_severity=sev_map.get(severity, "info"),
        event_provider=service or source,
        cloud_provider="gcp",
        cloud_account=project,
        cloud_region=rec.get("resource", {}).get("labels", {}).get("location", ""),
        cloud_service=service,
        user_name=principal,
        source_ip=ip if isinstance(ip, str) else "",
        resource_id=resource if isinstance(resource, str) else "",
        resource_arn=resource if isinstance(resource, str) else "",
        related_user=[principal] if principal else [],
        related_resource=[resource] if resource else [],
        message=f"{method or service} on {resource or project}",
        case_id=ctx.case_id,
        ventra_source=source,
        raw=rec,
    )


def _register_audit(name: str) -> None:
    @register(name)
    def _normalize(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
        for rec in records:
            yield _audit_event(rec, ctx, name)

    _normalize.__name__ = f"normalize_{name}"


for _src in _AUDIT_SOURCES:
    _register_audit(_src)
