"""Time window parsing for acquisition specs."""

from __future__ import annotations

from datetime import UTC, datetime

from collector.engine.run_common import parse_window


def test_date_only_until_is_end_of_day() -> None:
    tw = parse_window("2026-06-21", "2026-06-22")
    assert tw.since == datetime(2026, 6, 21, 0, 0, 0, tzinfo=UTC)
    assert tw.until == datetime(2026, 6, 22, 23, 59, 59, 999999, tzinfo=UTC)


def test_date_only_since_is_start_of_day() -> None:
    tw = parse_window("2026-06-21", None)
    assert tw.since == datetime(2026, 6, 21, 0, 0, 0, tzinfo=UTC)
    assert tw.until is None


def test_rfc3339_until_is_exact() -> None:
    tw = parse_window("2026-06-21", "2026-06-22T12:30:00Z")
    assert tw.until == datetime(2026, 6, 22, 12, 30, 0, tzinfo=UTC)
