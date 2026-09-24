"""Kubernetes Events normalizer (on-prem).

Events come from the ``kubernetes`` client's ``.to_dict()`` (snake_case keys). ``Warning``
events and the flagged reasons the collector marks (OOMKilled, BackOff, FailedMount, image
pulls, evictions) surface with raised severity so they show up in the timeline.

The collector reads both Event APIs, and they do not share a schema: ``core/v1`` uses
``involved_object`` / ``message`` / ``last_timestamp``, while ``events.k8s.io/v1`` uses
``regarding`` / ``note`` / ``event_time``. Every field here is resolved across both spellings
so a record normalizes identically whichever view it arrived from.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

_HIGH_REASONS = {"oomkilling", "oomkilled", "evicted", "failedmount", "backoff"}
_MEDIUM_REASONS = {"failed", "failedscheduling", "killing", "unhealthy"}


def _timestamp(rec: dict[str, Any]) -> str:
    # events.k8s.io/v1 prefers event_time and keeps the legacy fields under deprecated_*.
    for key in (
        "last_timestamp",
        "lastTimestamp",
        "event_time",
        "eventTime",
        "deprecated_last_timestamp",
        "deprecatedLastTimestamp",
        "first_timestamp",
        "firstTimestamp",
        "deprecated_first_timestamp",
    ):
        val = rec.get(key)
        if val:
            return str(val)
    meta = rec.get("metadata") or {}
    return str(meta.get("creation_timestamp") or meta.get("creationTimestamp") or "")


def _subject(rec: dict[str, Any]) -> dict[str, Any]:
    """The object the event is about: ``involved_object`` (core/v1) or ``regarding`` (modern)."""
    for key in ("involved_object", "involvedObject", "regarding"):
        val = rec.get(key)
        if isinstance(val, dict) and val:
            return val
    return {}


def _note(rec: dict[str, Any]) -> str:
    """The human-readable text: ``message`` (core/v1) or ``note`` (events.k8s.io/v1)."""
    for key in ("message", "note"):
        val = rec.get(key)
        if val:
            return str(val)
    return ""


def _reporting_node(rec: dict[str, Any]) -> str:
    source = rec.get("source") or {}
    if isinstance(source, dict) and source.get("host"):
        return str(source["host"])
    for key in ("reporting_instance", "reportingInstance", "deprecated_source"):
        val = rec.get(key)
        if isinstance(val, str) and val:
            return val
        if isinstance(val, dict) and val.get("host"):
            return str(val["host"])
    return ""


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
        involved = _subject(rec)
        ns = involved.get("namespace", "")
        kind = involved.get("kind", "")
        obj_name = involved.get("name", "")
        target = "/".join(p for p in (ns, kind, obj_name) if p)
        cluster = rec.get("_ventra_cluster", ctx.account_id)
        node = _reporting_node(rec)
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
            message=f"{reason}: {_note(rec)}".strip(": "),
            case_id=ctx.case_id,
            ventra_source="k8s_events",
            raw=rec,
        )
