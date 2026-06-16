"""Azure NSG flow logs → network events (same shape as VPC flow where possible)."""

from __future__ import annotations

import ipaddress
from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


@register("nsg_flow")
def normalize_nsg_flow(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        src = rec.get("srcaddr") or rec.get("source_ip") or ""
        dst = rec.get("dstaddr") or rec.get("dest_ip") or ""
        action = (rec.get("action") or "ALLOW").upper()
        try:
            nbytes = int(rec.get("bytes", 0) or 0)
            dport = int(rec.get("dstport", 0) or 0)
        except (TypeError, ValueError):
            nbytes, dport = 0, 0
        outcome = "failure" if action == "DENY" else "success"
        severity = "info"
        if action == "DENY":
            severity = "low"
        if _is_public(dst) and nbytes > 1_000_000:
            severity = "medium"
        ts = rec.get("timestamp") or rec.get("log_time") or ""
        yield UnifiedEvent(
            timestamp=ts,
            event_kind="event",
            event_category=["network"],
            event_action=action.lower(),
            event_outcome=outcome,
            event_severity=severity,
            event_provider="nsg_flow",
            cloud_provider="azure",
            cloud_account=ctx.account_id,
            cloud_region=rec.get("_ventra_region", ""),
            cloud_service="network",
            source_ip=src,
            dest_ip=dst,
            dest_port=dport or None,
            dest_bytes=nbytes or None,
            related_ip=[ip for ip in (src, dst) if ip],
            related_resource=[rec.get("resource_id", "")] if rec.get("resource_id") else [],
            message=f"{action} {src} -> {dst}:{dport}",
            case_id=ctx.case_id,
            ventra_source="nsg_flow",
            raw=rec,
        )
