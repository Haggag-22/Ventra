"""VPC Flow Logs normalizer → network events.

Handles both shapes the collector emits: CloudWatch Logs flow records (a ``message`` field
holding the space-delimited v2 flow log line) and already-structured records. Egress to
public IPs and REJECT flows are the exfil/recon lenses the Network panel renders.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

# Default VPC Flow Logs v2 field order.
V2_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status",
]


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def _parse_line(message: str) -> dict[str, Any] | None:
    parts = message.split()
    if len(parts) < len(V2_FIELDS):
        return None
    return dict(zip(V2_FIELDS, parts))


@register("vpc_flow")
def normalize_vpc_flow(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        # GCP Cloud Logging export (jsonPayload.connection)
        if rec.get("jsonPayload") or rec.get("_ventra_project_id"):
            payload = rec.get("jsonPayload") or rec.get("payload") or {}
            if not isinstance(payload, dict):
                payload = {}
            conn = payload.get("connection") or {}
            src = conn.get("src_ip") or payload.get("src_ip") or ""
            dst = conn.get("dest_ip") or payload.get("dest_ip") or ""
            project = rec.get("_ventra_project_id") or ctx.account_id
            yield UnifiedEvent(
                timestamp=rec.get("timestamp") or "",
                event_kind="event",
                event_category=["network"],
                event_action="flow",
                event_outcome="success",
                event_severity="info",
                event_provider="vpc_flow",
                cloud_provider="gcp",
                cloud_account=project,
                cloud_region=rec.get("resource", {}).get("labels", {}).get("zone", ""),
                cloud_service="compute",
                source_ip=src,
                dest_ip=dst,
                related_ip=[x for x in (src, dst) if x],
                message=f"FLOW {src} -> {dst}",
                case_id=ctx.case_id,
                ventra_source="vpc_flow",
                raw=rec,
            )
            continue

        flow = rec
        if "message" in rec and "srcaddr" not in rec:
            parsed = _parse_line(rec["message"])
            if parsed is None:
                continue
            flow = parsed
            flow["_ventra_region"] = rec.get("_ventra_region", "")

        src = flow.get("srcaddr", "")
        dst = flow.get("dstaddr", "")
        action = (flow.get("action", "") or "").upper()
        try:
            nbytes = int(flow.get("bytes", 0) or 0)
            dport = int(flow.get("dstport", 0) or 0)
        except (TypeError, ValueError):
            nbytes, dport = 0, 0

        outcome = "failure" if action == "REJECT" else "success"
        severity = "info"
        # Heuristics the Network panel leans on; enrichment refines these.
        if action == "REJECT":
            severity = "low"
        if _is_public(dst) and nbytes > 1_000_000:
            severity = "medium"  # sizeable egress to a public IP

        ts = ""
        if flow.get("start"):
            try:
                from datetime import datetime, timezone

                ts = datetime.fromtimestamp(int(flow["start"]), tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (ValueError, OSError):
                ts = ""

        yield UnifiedEvent(
            timestamp=ts,
            event_kind="event",
            event_category=["network"],
            event_action=action.lower() or "flow",
            event_outcome=outcome,
            event_severity=severity,
            event_provider="vpc_flow",
            cloud_provider="aws",
            cloud_account=flow.get("account_id", ctx.account_id),
            cloud_region=flow.get("_ventra_region", ""),
            cloud_service="vpc",
            source_ip=src,
            dest_ip=dst,
            dest_port=dport or None,
            dest_bytes=nbytes or None,
            related_ip=[ip for ip in (src, dst) if ip],
            related_resource=[flow.get("interface_id", "")] if flow.get("interface_id") else [],
            message=f"{action or 'FLOW'} {src} -> {dst}:{dport} ({nbytes} bytes)",
            case_id=ctx.case_id,
            ventra_source="vpc_flow",
            raw=flow,
        )
