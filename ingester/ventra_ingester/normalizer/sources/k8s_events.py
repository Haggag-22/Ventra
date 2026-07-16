"""Kubernetes Events normalizer (on-prem).

Events come from the ``kubernetes`` client's ``.to_dict()`` (snake_case keys). ``Warning``
events and the flagged reasons the collector marks (OOMKilled, BackOff, FailedMount, image
pulls, evictions) surface with raised severity so they show up in the timeline.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

_HIGH_REASONS = {"oomkilling", "oomkilled", "evicted", "failedmount", "backoff"}
_MEDIUM_REASONS = {"failed", "failedscheduling", "killing", "unhealthy"}


def _timestamp(rec: dict[str, Any]) -> str:
    for key in ("last_timestamp", "event_time", "first_timestamp"):
        val = rec.get(key)
        if val:
            return str(val)
    meta = rec.get("metadata") or {}
    return str(meta.get("creation_timestamp") or "")


def _severity(reason: str, etype: str) -> str:
    r = reason.lower()
    if r in _HIGH_REASONS:
        return "high"
    if r in _MEDIUM_REASONS or etype == "Warning":
        return "medium"
    return "info"


@register("k8s_events")
def normalize_k8s_events(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        reason = str(rec.get("reason", ""))
        etype = str(rec.get("type", ""))
        involved = rec.get("involved_object") or rec.get("involvedObject") or {}
        ns = involved.get("namespace", "")
        kind = involved.get("kind", "")
        obj_name = involved.get("name", "")
        target = "/".join(p for p in (ns, kind, obj_name) if p)
        cluster = rec.get("_ventra_cluster", ctx.account_id)
        source = rec.get("source") or {}
        node = source.get("host", "") if isinstance(source, dict) else ""
        yield UnifiedEvent(
            timestamp=_timestamp(rec),
            event_kind="event",
            event_category=["kubernetes"],
            event_action=reason,
            event_outcome="failure" if etype == "Warning" else "success",
            event_severity=_severity(reason, etype),
            event_provider="k8s_events",
            cloud_provider="kubernetes",
            cloud_account=cluster,
            cloud_region=node,
            cloud_service="kubernetes",
            resource_type=kind or "object",
            resource_id=target or cluster,
            related_resource=[r for r in (cluster, target) if r],
            message=f"{reason}: {rec.get('message', '')}".strip(": "),
            case_id=ctx.case_id,
            ventra_source="k8s_events",
            raw=rec,
        )
