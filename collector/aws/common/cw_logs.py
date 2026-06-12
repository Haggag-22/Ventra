"""Bounded reader for CloudWatch Logs-delivered logs (EKS audit, Route53 Resolver to CW).

One transport, many consumers: time-windowed ``FilterLogEvents`` with an optional stream
prefix, hard record caps, and typed-gap translation so a missing/denied log group is
recorded as evidence rather than crashing the run.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ...lib.models import GapReason
from ..client_factory import AccessDenied, ServiceNotEnabled

MAX_CW_RECORDS = 200_000


def collect_cw_log_events(
    cf,
    region: str,
    log_group: str,
    start: datetime,
    end: datetime,
    gaps: list[tuple[str, GapReason, str]],
    gap_name: str,
    *,
    stream_prefix: str | None = None,
    max_records: int = MAX_CW_RECORDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull events from one log group in the window; returns (events, stats)."""
    stats: dict[str, Any] = {
        "log_group": log_group,
        "region": region,
        "records": 0,
        "truncated": False,
    }
    events: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {
        "logGroupName": log_group,
        "startTime": int(start.timestamp() * 1000),
        "endTime": int(end.timestamp() * 1000),
    }
    if stream_prefix:
        kwargs["logStreamNamePrefix"] = stream_prefix

    try:
        for ev in cf.paginate("logs", region, "filter_log_events", "events", **kwargs):
            if len(events) >= max_records:
                stats["truncated"] = True
                gaps.append(
                    (
                        gap_name,
                        GapReason.COLLECTOR_ERROR,
                        f"{log_group}: truncated at {max_records} records; "
                        "narrow the window (--since/--until) for full coverage.",
                    )
                )
                break
            ev["_ventra_region"] = region
            ev["_ventra_log_group"] = log_group
            events.append(ev)
            stats["records"] += 1
    except AccessDenied as exc:
        gaps.append((gap_name, GapReason.ACCESS_DENIED, f"{log_group}: {exc.message}"))
    except ServiceNotEnabled as exc:
        gaps.append(
            (gap_name, GapReason.NOT_PRESENT, f"{log_group}: log group not found ({exc.message})")
        )
    return events, stats
