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

import re
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
        return _iso(datetime.fromtimestamp(micros / 1_000_000, tz=UTC))
    return str(rec.get("_ventra_timestamp") or "")


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- non-systemd fallback lines ---------------------------------------------------------------
#
# Lines read from /var/log/syslog or /var/log/kubelet.log carry their time only in the text.
# rsyslog's default is RFC 3339 ("2026-09-22T22:25:53.300220+00:00 host prog[pid]: msg"); older
# setups use BSD syslog ("Sep 26 06:59:33 host prog[pid]: msg") and kubelet.log is klog
# ("I0926 06:59:33.123456   1234 file.go:12] msg"). The last two omit the year.

_RFC3339_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
_BSD_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
_KLOG = re.compile(
    r"^(?P<level>[IWEF])(?P<mon>\d{2})(?P<day>\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
    r"\d+\s+(?P<msg>.*)$"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1
    )
}
# klog severity letter -> syslog priority, so _severity() treats both alike.
_KLOG_PRIORITY = {"I": 6, "W": 4, "E": 3, "F": 2}


def _parse_dt(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _yearless(month: int, day: int, clock: str, collected: datetime | None) -> datetime | None:
    """Pin a year-less log time to the collection year, stepping back a year if that lands in
    the future (a December line collected in January). Times are taken as UTC."""
    ref = collected or datetime.now(UTC)
    try:
        hh, mm, ss = (int(x) for x in clock.split(":"))
        dt = datetime(ref.year, month, day, hh, mm, ss, tzinfo=UTC)
        if dt > ref:
            dt = dt.replace(year=ref.year - 1)
    except ValueError:  # Feb 29 in a non-leap year, bad clock
        return None
    return dt


def parse_log_line(line: str, collected_at: str = "") -> dict[str, Any]:
    """Split a plain log line into ``timestamp`` / ``program`` / ``message`` / ``priority``.

    Fields that can't be recovered are left out, so callers keep their own defaults.
    """
    collected = _parse_dt(collected_at) if collected_at else None
    if m := _RFC3339_SYSLOG.match(line):
        dt = _parse_dt(m["ts"])
        out: dict[str, Any] = {"program": m["prog"], "host": m["host"], "message": m["msg"]}
        if dt:
            out["timestamp"] = _iso(dt)
        return out
    if m := _BSD_SYSLOG.match(line):
        out = {"program": m["prog"], "host": m["host"], "message": m["msg"]}
        dt = _yearless(_MONTHS.get(m["mon"], 0), int(m["day"]), m["time"], collected)
        if dt:
            out["timestamp"] = _iso(dt)
        return out
    if m := _KLOG.match(line):
        out = {"message": m["msg"], "priority": _KLOG_PRIORITY[m["level"]]}
        dt = _yearless(int(m["mon"]), int(m["day"]), m["time"], collected)
        if dt:
            out["timestamp"] = _iso(dt)
        return out
    return {}


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
        timestamp = _journal_timestamp(rec)
        priority_rec = rec
        if rec.get("_ventra_log_file"):
            # Non-systemd fallback: the time, program and level live in the line itself.
            parsed = parse_log_line(message, ctx.collected_at)
            timestamp = timestamp or parsed.get("timestamp", "")
            unit = parsed.get("program") or unit
            message = parsed.get("message") or message
            if "priority" in parsed and "PRIORITY" not in rec:
                priority_rec = {**rec, "PRIORITY": parsed["priority"]}
        yield UnifiedEvent(
            timestamp=timestamp,
            event_kind="event",
            event_category=["kubernetes", "host"],
            event_action=unit,
            event_outcome="unknown",
            event_severity=_severity(priority_rec, message),
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
