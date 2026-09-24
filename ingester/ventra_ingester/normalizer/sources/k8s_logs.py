"""Kubernetes node-plane log normalizers (on-prem).

Three collectors capture systemd-journal records — kubelet, the container runtime, and
etcd / the merged server journal on k3s-style distros. They share a shape: each record
already carries its node provenance (``_ventra_node``, ``_ventra_runtime``) because the
node-plane base stamps every record, so the normalizer's job is to put them on one timeline
alongside the audit log.

Container logs from ``/var/log/pods`` are file evidence (inventory), not per-line timeline
events.

Journal severity follows syslog ``PRIORITY``: 0–3 (emerg…err) is the runtime telling you
something failed, which is exactly what an analyst wants surfaced next to an audit event.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

# syslog priority -> Ventra severity. 4 (warning) stays low so healthy-but-noisy units do
# not crowd out real failures.
_PRIORITY_SEVERITY = {0: "critical", 1: "critical", 2: "high", 3: "medium", 4: "low"}

# Journal message fragments worth raising regardless of priority — the runtime-level traces
# of image pulls and container lifecycle an investigation actually turns on.
_NOTABLE = (
    ("failed to pull image", "medium"),
    ("error syncing pod", "medium"),
    ("oom-killed", "high"),
    ("oomkill", "high"),
    ("container died", "low"),
    ("unauthorized", "high"),
    ("permission denied", "medium"),
    ("certificate", "low"),
)


def _journal_timestamp(rec: dict[str, Any]) -> str:
    """journald ``__REALTIME_TIMESTAMP`` is microseconds since the epoch, as a string."""
    for key in ("__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"):
        raw = rec.get(key)
        if raw is None:
            continue
        try:
            micros = int(str(raw))
        except (TypeError, ValueError):
            continue
        return datetime.fromtimestamp(micros / 1_000_000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Non-systemd fallback files carry no timestamp of their own.
    return str(rec.get("_ventra_timestamp") or "")


def _message(rec: dict[str, Any]) -> str:
    msg = rec.get("MESSAGE")
    if isinstance(msg, list):  # journald can return a byte array for binary messages
        return " ".join(str(m) for m in msg)
    return str(msg or "")


def _severity(rec: dict[str, Any], message: str) -> str:
    try:
        priority = int(str(rec.get("PRIORITY", "6")))
    except (TypeError, ValueError):
        priority = 6
    severity = _PRIORITY_SEVERITY.get(priority, "info")
    lowered = message.lower()
    rank = ["info", "low", "medium", "high", "critical"]
    for fragment, sev in _NOTABLE:
        if fragment in lowered and rank.index(sev) > rank.index(severity):
            severity = sev
    return severity


def _unit(rec: dict[str, Any], default: str) -> str:
    for key in ("_SYSTEMD_UNIT", "UNIT", "SYSLOG_IDENTIFIER"):
        val = rec.get(key)
        if val:
            return str(val)
    return default


def _journal_events(
    records: list[dict], ctx: NormalizeContext, provider: str, default_unit: str
) -> Iterator[UnifiedEvent]:
    for rec in records:
        if rec.get("container_id"):
            # runtime_logs also ships crictl inspect rows; those are state, not log lines.
            yield _inspect_event(rec, ctx, provider)
            continue
        if rec.get("_ventra_note"):
            continue  # collector bookkeeping row (e.g. inspect cap notice)
        message = _message(rec)
        if not message:
            continue
        node = str(rec.get("_ventra_node") or "")
        cluster = str(rec.get("_ventra_cluster") or ctx.account_id)
        unit = _unit(rec, rec.get("_ventra_component") or default_unit)
        yield UnifiedEvent(
            timestamp=_journal_timestamp(rec),
            event_kind="event",
            event_category=["kubernetes", "host"],
            event_action=unit,
            event_outcome="unknown",
            event_severity=_severity(rec, message),
            event_provider=provider,
            cloud_provider="kubernetes",
            cloud_account=cluster,
            cloud_region=node,
            cloud_service="kubernetes",
            resource_type="node",
            resource_id=node or cluster,
            related_resource=[r for r in (cluster, node) if r],
            message=message,
            case_id=ctx.case_id,
            ventra_source=provider,
            raw=rec,
        )


def _inspect_event(rec: dict[str, Any], ctx: NormalizeContext, provider: str) -> UnifiedEvent:
    """One ``crictl inspect`` row — the live container as the runtime sees it."""
    node = str(rec.get("_ventra_node") or "")
    cluster = str(rec.get("_ventra_cluster") or ctx.account_id)
    ns = str(rec.get("namespace") or "")
    pod = str(rec.get("pod") or "")
    container = str(rec.get("container") or "")
    cid = str(rec.get("container_id") or "")
    target = "/".join(p for p in (ns, pod, container) if p)
    return UnifiedEvent(
        # Live runtime state, so it is true as of collection; the runtime's own created-at
        # stays available inside the nested inspect payload.
        timestamp=ctx.collected_at,
        event_kind="state",
        event_category=["kubernetes", "configuration"],
        event_action="ContainerRuntimeInspect",
        event_outcome="failure" if rec.get("error") else "success",
        event_severity="info",
        event_provider=provider,
        cloud_provider="kubernetes",
        cloud_account=cluster,
        cloud_region=node,
        cloud_service="kubernetes",
        resource_type="container",
        resource_id=target or cid,
        related_resource=[r for r in (cluster, node, target, cid) if r],
        message=f"Runtime state for {target or cid} on {node or 'node'}"
        + (f" — {rec.get('error')}" if rec.get("error") else ""),
        case_id=ctx.case_id,
        ventra_source=provider,
        raw=rec,
    )


@register("k8s_kubelet_logs")
def normalize_k8s_kubelet_logs(records: list[dict], ctx: NormalizeContext):
    return _journal_events(records, ctx, "k8s_kubelet_logs", "kubelet.service")


@register("k8s_runtime_logs")
def normalize_k8s_runtime_logs(records: list[dict], ctx: NormalizeContext):
    return _journal_events(records, ctx, "k8s_runtime_logs", "containerd.service")


@register("k8s_etcd")
def normalize_k8s_etcd(records: list[dict], ctx: NormalizeContext):
    return _journal_events(records, ctx, "k8s_etcd", "etcd.service")
