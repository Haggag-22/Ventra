"""Adaptive time-window splitting for Search-UnifiedAuditLog (5000 events/call cap)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from collector.lib.limits import records_unlimited

from .ual_common import API_CAP_PER_SEARCH_CALL

if TYPE_CHECKING:
    from collector.lib.base import JsonlWriter

MIN_WINDOW = timedelta(minutes=1)


def shrink_threshold(target_events_per_window: int) -> int:
    return min(max(int(target_events_per_window * 1.5), 1), API_CAP_PER_SEARCH_CALL - 1)


def collect_adaptive(
    start: datetime,
    end: datetime,
    *,
    search_window: Callable[[datetime, datetime], list[dict[str, Any]]],
    target_events_per_window: int,
    max_records: int,
    writer: JsonlWriter | None = None,
) -> tuple[int, list[str]]:
    """Split intervals when a window is too dense; return record count + truncation warnings."""
    threshold = shrink_threshold(target_events_per_window)
    stack: list[tuple[datetime, datetime]] = [(start, end)]
    warnings: list[str] = []
    count = 0

    while stack and (records_unlimited(max_records) or count < max_records):
        win_start, win_end = stack.pop()
        if win_end <= win_start:
            continue
        batch = search_window(win_start, win_end)
        batch_count = len(batch)
        width = win_end - win_start

        if batch_count >= threshold and width > MIN_WINDOW:
            mid = win_start + width / 2
            stack.append((mid, win_end))
            stack.append((win_start, mid))
            continue

        if batch_count >= API_CAP_PER_SEARCH_CALL and width <= MIN_WINDOW:
            warnings.append(
                f"{win_start.isoformat()}–{win_end.isoformat()}: hit {API_CAP_PER_SEARCH_CALL}-event "
                "API cap at minimum window — some events may be missing."
            )

        for rec in batch:
            if writer is not None:
                writer.write_record(rec)
            count += 1
            if not records_unlimited(max_records) and count >= max_records:
                warnings.append(
                    f"Stopped at global cap ({max_records:,} records); narrow filters "
                    "(--ual-users, --ual-operations) or time window for full coverage."
                )
                return count, warnings

    return count, warnings
