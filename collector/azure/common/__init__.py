"""Shared helpers for Azure collectors (time windows, OData filters)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...lib.models import TimeWindow


def window_bounds(window: TimeWindow, default_days: int) -> tuple[datetime, datetime]:
    """Resolve a collection window, defaulting the start to ``default_days`` ago.

    Azure log sources have shorter, source-specific retention than CloudTrail (sign-in logs
    ~30 days on Entra P1, Activity Log ~90 days), so each collector passes its own default.
    """
    end = window.until or datetime.now(UTC)
    start = window.since or (end - timedelta(days=default_days))
    return start, end


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def graph_time_filter(field: str, start: datetime, end: datetime) -> str:
    """OData ``$filter`` over a Graph datetime field, e.g. ``createdDateTime``."""
    return f"{field} ge {_iso(start)} and {field} le {_iso(end)}"


def arm_time_filter(start: datetime, end: datetime) -> str:
    """Activity Log filter — ARM requires the timestamps quoted."""
    return f"eventTimestamp ge '{_iso(start)}' and eventTimestamp le '{_iso(end)}'"
