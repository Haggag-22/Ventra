"""Unit tests for UAL adaptive window splitting."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from collector.engine.api.azure.m365.ual_adaptive import collect_adaptive


def test_adaptive_splits_dense_window() -> None:
    start = datetime(2026, 6, 1, tzinfo=UTC)
    end = datetime(2026, 6, 2, tzinfo=UTC)
    calls: list[tuple[datetime, datetime]] = []

    def search_window(win_start: datetime, win_end: datetime) -> list[dict]:
        calls.append((win_start, win_end))
        width = win_end - win_start
        if width > timedelta(hours=12):
            return [{"i": i} for i in range(4600)]
        return [{"i": i} for i in range(10)]

    records, warnings = collect_adaptive(
        start, end, search_window=search_window, target_events_per_window=3000, max_records=50_000
    )
    assert len(records) > 0
    assert len(calls) > 1


def test_adaptive_reports_global_cap() -> None:
    start = datetime(2026, 6, 1, tzinfo=UTC)
    end = datetime(2026, 6, 1, 1, tzinfo=UTC)

    def search_window(_s: datetime, _e: datetime) -> list[dict]:
        return [{"n": 1}] * 100

    records, warnings = collect_adaptive(
        start, end, search_window=search_window, target_events_per_window=3000, max_records=50
    )
    assert len(records) == 50
    assert any("global cap" in w for w in warnings)
