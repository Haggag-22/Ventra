"""Collector-level test: the fail-closed timestamp exclusion (Task 2) surfaces as a gap.

Verifies that when the export read reports records dropped for unparseable/missing timestamps
(via the read ``stats`` dict), GcpLoggingCollector records a GapReason.UNPARSEABLE_TIMESTAMP so
operators can see how many records were excluded and why — data doesn't vanish silently.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from collector.engine.api.gcp.common.logging_collector import GcpLoggingCollector
from collector.lib.models import CollectionContext, GapReason, TimeWindow


class _Collector(GcpLoggingCollector):
    name = "cloud_audit_admin"
    log_filter = 'logName:"cloudaudit.googleapis.com%2Factivity"'


class _FakeFactory:
    """Mimics the GCS export path: yields rows AND reports the exclusion count in ``stats``."""

    def __init__(self, rows, excluded_ts: int) -> None:
        self._rows = rows
        self._excluded = excluded_ts

    def iter_log_entries_all_projects(self, projects, *, stats=None, **kwargs):
        if stats is not None and self._excluded:
            stats["excluded_unparseable_timestamp"] = self._excluded
        for r in self._rows:
            yield "demo", r


def _ctx(tmp_path: Path, cf) -> CollectionContext:
    (tmp_path / "sources").mkdir(parents=True, exist_ok=True)
    return CollectionContext(
        cloud="gcp",
        account_id="org",
        regions=[],
        time_window=TimeWindow(
            since=datetime(2026, 1, 1, tzinfo=UTC), until=datetime(2026, 1, 31, tzinfo=UTC)
        ),
        staging=tmp_path,
        case_id="CASE-TS",
        project_ids=["demo"],
        gcp_log_backend={"mode": "gcs", "gcs": {"bucket": "demo-logs"}},
        client_factory=cf,
    )


def _row() -> dict:
    return {
        "logName": "projects/demo/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": "2026-01-15T10:00:00Z",
        "insertId": "a1",
    }


def test_unparseable_timestamp_exclusions_surface_as_gap(tmp_path) -> None:
    cf = _FakeFactory([_row(), _row()], excluded_ts=3)
    result = _Collector(_ctx(tmp_path, cf)).collect()

    ts_gaps = [g for g in result.gaps if g[1] == GapReason.UNPARSEABLE_TIMESTAMP]
    assert len(ts_gaps) == 1
    assert "3" in ts_gaps[0][2]
    assert "timestamp" in ts_gaps[0][2].lower()
    # Records that DID collect are unaffected; the gap makes the status PARTIAL, not a silent drop.
    assert result.record_count == 2


def test_no_gap_when_no_exclusions(tmp_path) -> None:
    cf = _FakeFactory([_row()], excluded_ts=0)
    result = _Collector(_ctx(tmp_path, cf)).collect()
    assert not [g for g in result.gaps if g[1] == GapReason.UNPARSEABLE_TIMESTAMP]
