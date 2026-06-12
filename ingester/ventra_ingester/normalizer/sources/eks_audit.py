"""EKS Kubernetes API-server audit-log normalizer.

Each record is one Kubernetes audit event. Only the ``ResponseComplete`` stage is
normalized (``RequestReceived`` would duplicate every call). Sensitive verbs — exec into
pods, secret reads, cluster-role-binding changes — get severity bumps so they surface in
the timeline without the analyst knowing Kubernetes internals.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

# (verb-or-*, resource[/subresource]) -> severity. First match wins.
_SENSITIVE: tuple[tuple[str, str, str], ...] = (
    ("create", "pods/exec", "high"),
    ("create", "pods/attach", "high"),
    ("create", "pods/portforward", "medium"),
    ("*", "secrets", "medium"),
    ("create", "clusterrolebindings", "high"),
    ("update", "clusterrolebindings", "high"),
    ("patch", "clusterrolebindings", "high"),
    ("delete", "clusterrolebindings", "high"),
    ("create", "rolebindings", "medium"),
    ("create", "mutatingwebhookconfigurations", "high"),
    ("delete", "events", "medium"),  # log tampering inside the cluster
)


def _severity(verb: str, resource: str) -> str:
    for v, r, sev in _SENSITIVE:
        if (v == "*" or v == verb) and resource.startswith(r):
            return sev
    return "info"


def _resource_path(obj: dict[str, Any]) -> str:
    resource = obj.get("resource", "")
    sub = obj.get("subresource", "")
    return f"{resource}/{sub}" if sub else resource


@register("eks_audit")
def normalize_eks_audit(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        if rec.get("stage") == "RequestReceived":
            continue
        verb = rec.get("verb", "")
        obj = rec.get("objectRef") or {}
        resource = _resource_path(obj)
        user = (rec.get("user") or {}).get("username", "")
        ips = rec.get("sourceIPs") or []
        ip = ips[0] if ips else ""
        code = (rec.get("responseStatus") or {}).get("code")
        decision = (rec.get("annotations") or {}).get("authorization.k8s.io/decision", "")
        denied = decision == "forbid" or (isinstance(code, int) and code >= 400)
        severity = _severity(verb, resource)
        if denied and severity == "info":
            severity = "low"
        name = obj.get("name", "")
        ns = obj.get("namespace", "")
        target = "/".join(p for p in (ns, resource, name) if p)
        cluster = rec.get("_ventra_cluster", "")
        yield UnifiedEvent(
            timestamp=rec.get("stageTimestamp", rec.get("requestReceivedTimestamp", "")),
            event_kind="event",
            event_category=["kubernetes"],
            event_action=f"{verb} {resource}".strip(),
            event_outcome="failure" if denied else "success",
            event_severity=severity,
            event_provider="eks_audit",
            cloud_account=ctx.account_id,
            cloud_region=rec.get("_ventra_region", ""),
            cloud_service="eks",
            user_name=user,
            source_ip=ip,
            ua_original=rec.get("userAgent", ""),
            resource_type=resource or "cluster",
            resource_id=target or cluster,
            related_ip=[ip] if ip else [],
            related_user=[user] if user else [],
            related_resource=[r for r in (cluster, target) if r],
            message=f"{user or 'unknown'} {verb} {target or resource}"
            + (f" on {cluster}" if cluster else "")
            + (" — DENIED" if denied else ""),
            case_id=ctx.case_id,
            ventra_source="eks_audit",
            raw=rec,
        )
