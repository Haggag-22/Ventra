"""GCP Cloud Audit Logs → unified events, plus the Load Balancer request-log family.

Cloud Audit Logs (protoPayload-shaped) and the LB `requests` log (jsonPayload/httpRequest-
shaped) are structurally different, but both can arrive tagged with a *shared-table* source
name (``cloud_audit_data`` / ``load_balancer``) when the collector engine deduplicates a
subset collector into its broad-stream parent (see ``GCP_SUBSET_OF`` in
``collector/engine/gcp_log_backend.py`` — duplicated here rather than imported, since this
package has no dependency on ``collector/``). Content-based reclassification below restores
the specific subset ``ventra_source`` per row so panel queries filtering on e.g.
``storage_access`` see the right rows regardless of whether dedup collapsed it into the
parent at collection time.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register
from .access_logs import _status_outcome

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
        "firewall_logs",
        "cloud_monitoring",
    }
)

# serviceName -> subset ventra_source, for rows read via the shared cloud_audit_data table.
# Mirrors COLLECTOR_MAP's _audit_view() entries in collector/engine/gcp_strategy_resolver.py.
_SERVICE_TO_SUBSET = {
    "login.googleapis.com": "login_events",
    "storage.googleapis.com": "storage_access",
    "bigquery.googleapis.com": "bigquery_audit",
    "secretmanager.googleapis.com": "secret_manager",
}

# Sources that read the shared Load Balancer `requests` log — jsonPayload/httpRequest-shaped,
# not protoPayload. All three dispatch through _lb_event; cloud_cdn/cloud_armor rows arrive
# either standalone (source already specific) or folded into load_balancer at collection time
# (reclassified below by content).
_LB_SOURCES = ("load_balancer", "cloud_cdn", "cloud_armor")


def _proto(rec: dict) -> dict[str, Any]:
    return rec.get("protoPayload") or {}


def _audit_event(rec: dict, ctx: NormalizeContext, source: str) -> UnifiedEvent:
    proto = _proto(rec)
    auth = proto.get("authenticationInfo") or {}
    req_meta = proto.get("requestMetadata") or {}
    resource = proto.get("resourceName") or rec.get("resource", {}).get("labels", {}).get("project_id", "")
    method = proto.get("methodName") or ""
    service = proto.get("serviceName") or ""
    principal = auth.get("principalEmail") or auth.get("principalSubject") or ""
    ip = req_meta.get("callerIp") or req_meta.get("callerSuppliedUserAgent", "")
    project = rec.get("_ventra_project_id") or ctx.account_id
    severity = (rec.get("severity") or "INFO").lower()
    sev_map = {"error": "high", "warning": "medium", "critical": "critical"}
    if source == "cloud_audit_data":
        source = _SERVICE_TO_SUBSET.get(service, source)
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


def _lb_event(rec: dict, ctx: NormalizeContext, source: str) -> UnifiedEvent:
    json_payload = rec.get("jsonPayload") or {}
    http = rec.get("httpRequest") or {}
    status = str(http.get("status") or "")
    method = http.get("requestMethod") or ""
    url = http.get("requestUrl") or ""
    ip = http.get("remoteIp") or ""
    labels = rec.get("resource", {}).get("labels", {})
    resource = labels.get("forwarding_rule_name") or labels.get("url_map_name") or ""
    project = rec.get("_ventra_project_id") or ctx.account_id

    if source == "load_balancer":
        if json_payload.get("cacheDecision") is not None:
            source = "cloud_cdn"
        elif (json_payload.get("enforcedSecurityPolicy") or {}).get("name"):
            source = "cloud_armor"

    return UnifiedEvent(
        timestamp=rec.get("timestamp") or "",
        event_kind="event",
        event_category=["network", "web"],
        event_action=method,
        event_outcome=_status_outcome(status),
        event_severity="info",
        event_provider="load_balancer",
        cloud_provider="gcp",
        cloud_account=project,
        cloud_region=labels.get("region", "") or labels.get("location", ""),
        cloud_service="compute.googleapis.com",
        source_ip=ip if isinstance(ip, str) else "",
        resource_type="load-balancer",
        resource_id=resource,
        related_ip=[ip] if ip else [],
        # AWS-format message ("METHOD target -> STATUS (resource)") — shared aggregations
        # in console/backend/app/store.py (web_dns_overview's edge_status/edge_paths) regex
        # this shape, so GCP LB rows must match it for those panels to see the data.
        message=f"{method} {url} → {status} ({resource})",
        case_id=ctx.case_id,
        ventra_source=source,
        raw=rec,
    )


def _register_lb(name: str) -> None:
    @register(name)
    def _normalize(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
        for rec in records:
            yield _lb_event(rec, ctx, name)

    _normalize.__name__ = f"normalize_{name}"


for _src in _LB_SOURCES:
    _register_lb(_src)
