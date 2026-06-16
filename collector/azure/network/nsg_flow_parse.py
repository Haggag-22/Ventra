"""Parse Azure NSG flow log records from storage blobs."""

from __future__ import annotations

from typing import Any


def parse_flow_tuple(flow_tuple: str) -> dict[str, str]:
    """Parse NSG flow log v2 tuple: ts,src,dst,srcport,dstport,proto,decision,state,dir."""
    parts = flow_tuple.split(",")
    if len(parts) < 10:
        return {"flow_tuple": flow_tuple}
    return {
        "timestamp": parts[0],
        "srcaddr": parts[1],
        "dstaddr": parts[2],
        "srcport": parts[3],
        "dstport": parts[4],
        "protocol": parts[5],
        "action": parts[6].upper(),
        "flow_state": parts[7],
        "direction": parts[8],
    }


def flatten_nsg_records(blob_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand nested NSG flow log JSON into flat flow records."""
    out: list[dict[str, Any]] = []
    for rec in blob_records:
        props = rec.get("properties") or {}
        resource_id = rec.get("resourceId") or rec.get("resource_id") or ""
        ts = rec.get("time") or rec.get("timestamp") or ""
        for flow_group in props.get("flows") or []:
            rule = flow_group.get("rule", "")
            for flow in flow_group.get("flows") or []:
                for tup in flow.get("flowTuples") or []:
                    parsed = parse_flow_tuple(str(tup))
                    parsed["rule"] = rule
                    parsed["resource_id"] = resource_id
                    parsed["log_time"] = ts
                    out.append(parsed)
    return out
