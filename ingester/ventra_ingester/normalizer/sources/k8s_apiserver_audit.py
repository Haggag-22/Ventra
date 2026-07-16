"""On-prem Kubernetes API-server audit-log normalizer.

Each record is one ``audit.k8s.io/v1`` event read from disk by ``k8s_apiserver_audit``. Only
the ``ResponseComplete`` / ``Panic`` stages are normalized (``RequestReceived`` would duplicate
every call). Sensitive verbs — exec into pods, secret reads, cluster-role-binding changes —
get severity bumps so they surface in the timeline without the analyst knowing Kubernetes
internals. Node provenance (``_ventra_node`` etc.) is carried through to ``cloud_region`` so an
analyst can trace a record back to its control-plane node.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

_SENSITIVE: tuple[tuple[str, str, str], ...] = (
    ("create", "pods/exec", "high"),
    ("create", "pods/attach", "high"),
    ("create", "pods/portforward", "medium"),
    # Reading secrets is the exfil signal — rank it high before the catch-all secrets rule.
    ("get", "secrets", "high"),
    ("list", "secrets", "high"),
    ("watch", "secrets", "high"),
    ("*", "secrets", "medium"),
    ("create", "clusterrolebindings", "high"),
    ("update", "clusterrolebindings", "high"),
    ("patch", "clusterrolebindings", "high"),
    ("delete", "clusterrolebindings", "high"),
    ("create", "rolebindings", "medium"),
    ("create", "mutatingwebhookconfigurations", "high"),
    ("delete", "events", "medium"),  # in-cluster log tampering
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


@register("k8s_apiserver_audit")
def normalize_k8s_apiserver_audit(
    records: list[dict], ctx: NormalizeContext
) -> Iterator[UnifiedEvent]:
    for rec in records:
        if rec.get("stage") == "RequestReceived":
            continue
        verb = rec.get("verb", "")
        obj = rec.get("objectRef") or {}
        resource = _resource_path(obj)
        user = (rec.get("user") or {}).get("username", "")
        impersonated = (rec.get("impersonatedUser") or {}).get("username", "")
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
        node = rec.get("_ventra_node", "")
        cluster = rec.get("_ventra_cluster", ctx.account_id)
        actors = [a for a in (user, impersonated) if a]
        yield UnifiedEvent(
            timestamp=rec.get("stageTimestamp", rec.get("requestReceivedTimestamp", "")),
            event_kind="event",
            event_category=["kubernetes"],
            event_action=f"{verb} {resource}".strip(),
            event_outcome="failure" if denied else "success",
            event_severity=severity,
            event_provider="k8s_apiserver_audit",
            cloud_provider="kubernetes",
            cloud_account=cluster,
            cloud_region=node,
            cloud_service="kube-apiserver",
            user_name=user,
            user_id=impersonated,
            source_ip=ip,
            ua_original=rec.get("userAgent", ""),
            resource_type=resource or "cluster",
            resource_id=target or cluster,
            related_ip=[ip] if ip else [],
            related_user=actors,
            related_resource=[r for r in (cluster, node, target) if r],
            message=f"{user or 'unknown'}"
            + (f" (as {impersonated})" if impersonated else "")
            + f" {verb} {target or resource}"
            + (f" on {node}" if node else "")
            + (" — DENIED" if denied else ""),
            case_id=ctx.case_id,
            ventra_source="k8s_apiserver_audit",
            raw=rec,
        )
