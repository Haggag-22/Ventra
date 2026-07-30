"""CloudWatch Logs normalizer → unified events.

Maps FilterLogEvents records (and any collector-added ``_ventra_*`` tags) into the
case timeline. Message body stays as the event message; the full CW payload is kept
in ``raw`` for the raw-log drawer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register


def _ts(rec: dict[str, Any]) -> str:
    raw = rec.get("timestamp") or rec.get("ingestionTime")
    if isinstance(raw, (int, float)):
        # CW FilterLogEvents timestamps are epoch milliseconds.
        ms = int(raw)
        if ms > 10_000_000_000:  # ms vs seconds
            return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat().replace("+00:00", "Z")
        return datetime.fromtimestamp(ms, tz=UTC).isoformat().replace("+00:00", "Z")
    if isinstance(raw, str) and raw:
        return raw
    return ""


@register("cloudwatch")
def normalize_cloudwatch(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        group = str(rec.get("_ventra_log_group") or rec.get("logGroupName") or "")
        stream = str(rec.get("logStreamName") or "")
        message = str(rec.get("message") or "")
        region = str(rec.get("_ventra_region") or "")
        yield UnifiedEvent(
            timestamp=_ts(rec),
            event_kind="event",
            event_category=["log"],
            event_action="cloudwatch_log",
            event_outcome="success",
            event_severity="info",
            event_provider="cloudwatch",
            cloud_provider="aws",
            cloud_account=ctx.account_id,
            cloud_region=region,
            cloud_service="logs",
            resource_type="log_group",
            resource_id=group or stream,
            message=message[:2000] if message else (group or "CloudWatch log event"),
            case_id=ctx.case_id,
            ventra_source="cloudwatch",
            raw=rec,
        )
