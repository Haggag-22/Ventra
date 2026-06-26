"""Shared flow-log collection: discover → read Storage blobs → flatten flow tuples.

VNet and NSG flow logs carry the same forensic content (5-tuple, allow/deny, bytes) but in
different blob schemas and tuple field orders, so each has its own flattener. Both produce the
same flat record shape the network normalizer consumes:

    {srcaddr, dstaddr, dstport, action, bytes, timestamp, resource_id, _ventra_region}
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import scoped_window
from collector.lib.scoping import filter_nsg_flow_logs, filter_vnet_flow_logs
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common.storage_logs import FLOW_CONTAINER, read_log_records

FlattenFn = Callable[[dict, str], Iterator[dict]]


def _iso_from_epoch(value: str) -> str:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return ""
    if n > 1_000_000_000_000:
        n //= 1000
    try:
        return datetime.fromtimestamp(n, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError, OverflowError):
        return ""


def _flat(parts_time: str, src: str, dst: str, dport: str, action: str,
          b1: str, b2: str, resource_id: str, region: str) -> dict[str, Any]:
    def _i(v: str) -> int:
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0
    return {
        "srcaddr": src,
        "dstaddr": dst,
        "dstport": _i(dport),
        "action": action,
        "bytes": _i(b1) + _i(b2),
        "timestamp": _iso_from_epoch(parts_time),
        "resource_id": resource_id,
        "_ventra_region": region,
    }


def flatten_nsg_record(rec: dict, region: str = "") -> Iterator[dict]:
    """NSG flow log v2: properties.flows[].flows[].flowTuples (decision A/D in field 7)."""
    rid = rec.get("resourceId", "")
    props = rec.get("properties") or {}
    for rule_group in props.get("flows") or []:
        for f in rule_group.get("flows") or []:
            for tup in f.get("flowTuples") or []:
                p = tup.split(",")
                if len(p) < 8:
                    continue
                action = "ALLOW" if p[7] == "A" else "DENY"
                b1 = p[10] if len(p) > 10 else ""
                b2 = p[12] if len(p) > 12 else ""
                yield _flat(p[0], p[1], p[2], p[4], action, b1, b2, rid, region)


def flatten_vnet_record(rec: dict, region: str = "") -> Iterator[dict]:
    """VNet flow log v4: properties.flowRecords.flows[].flowGroups[].flowTuples."""
    rid = rec.get("resourceId", "")
    props = rec.get("properties") or {}
    flow_records = props.get("flowRecords") or {}
    for flow in flow_records.get("flows") or []:
        target = flow.get("aclID") or rid
        for group in flow.get("flowGroups") or []:
            for tup in group.get("flowTuples") or []:
                p = tup.split(",")
                if len(p) < 8:
                    continue
                state = p[7] if len(p) > 7 else ""
                action = "DENY" if state == "D" else "ALLOW"
                b1 = p[10] if len(p) > 10 else ""
                b2 = p[12] if len(p) > 12 else ""
                yield _flat(p[0], p[1], p[2], p[4], action, b1, b2, target, region)


def _record_in_window(rec: dict[str, Any], start: datetime, end: datetime) -> bool:
    ts = rec.get("timestamp") or ""
    if not ts:
        return True
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return True
    return start <= dt <= end


def collect_flow_logs(collector, *, flow_type: str, flatten: FlattenFn) -> SourceResult:
    """Discover + read flow logs of ``flow_type`` ('vnet'|'nsg') across in-scope subscriptions."""
    cf = collector.ctx.client_factory
    name = collector.name
    params = collector.artifact_params()
    container = FLOW_CONTAINER[flow_type]
    gaps: list[tuple[str, GapReason, str]] = []
    records: list[dict] = []
    per_log: list[dict] = []
    any_enabled = False
    start, end = scoped_window(collector.ctx, name, default_days=7)
    window_start, window_end = (start, end) if start and end else (None, None)

    for sub in collector.ctx.subscription_ids:
        try:
            flow_logs = cf.network_flow_logs(sub)
        except AzureAccessDenied as exc:
            gaps.append((name, GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
            continue
        except AzureServiceNotEnabled as exc:
            gaps.append((name, GapReason.NOT_PRESENT, f"{sub}: {exc.message}"))
            continue
        if flow_type == "vnet":
            flow_logs = filter_vnet_flow_logs(flow_logs, params)
        else:
            flow_logs = filter_nsg_flow_logs(flow_logs, params)
        for fl in flow_logs:
            if fl.get("flow_type") != flow_type or not fl.get("enabled"):
                continue
            any_enabled = True
            before = len(records)
            try:
                cc = cf.container_client(fl["storage_id"], container)
                for rec in read_log_records(cc, start=window_start, end=window_end):
                    for flat in flatten(rec, ""):
                        if window_start is None or window_end is None or _record_in_window(flat, window_start, window_end):
                            records.append(flat)
            except AzureAccessDenied as exc:
                gaps.append((name, GapReason.ACCESS_DENIED, f"{fl['name']}: {exc.message}"))
            except AzureServiceNotEnabled as exc:
                gaps.append((name, GapReason.NOT_PRESENT, f"{fl['name']}: {exc.message}"))
            per_log.append(
                {"flow_log": fl["name"], "target": fl["target_resource_id"],
                 "records": len(records) - before}
            )

    if not any_enabled and not any(g[1] == GapReason.ACCESS_DENIED for g in gaps):
        gaps.append(
            (
                name,
                GapReason.LOGGING_NOT_CONFIGURED,
                f"No enabled {flow_type.upper()} flow logs in scope — network flow visibility gap.",
            )
        )

    files = []
    if records:
        files.append(collector.write_jsonl(records, "events.jsonl.gz"))
    collector.write_meta(
        {
            "source": name,
            "records": len(records),
            "flow_logs": per_log,
            "window": (
                {"since": start.isoformat(), "until": end.isoformat()}
                if start and end
                else collector.ctx.time_window.to_manifest()
            ),
            "artifact_parameters": params,
        }
    )

    status = SourceStatus.EMPTY
    if records:
        status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
    return SourceResult(
        name=name,
        status=status,
        files=files,
        record_count=len(records),
        gaps=gaps,
        notes=f"{len(records)} {flow_type} flow record(s) from {len(per_log)} flow log(s).",
    )
