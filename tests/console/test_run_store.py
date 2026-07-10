"""Run store CRUD tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "backend"))

from app.run_store import RunNotFound, RunStore  # noqa: E402


@pytest.fixture
def rs(tmp_path: Path) -> RunStore:
    return RunStore(tmp_path / "runs")


def test_create_and_list(rs: RunStore) -> None:
    rec = rs.create_run({"cloud": "aws", "case_id": "CASE-1"})
    assert rec["run_id"]
    assert rec["status"] == "pending"
    listed = rs.list_runs()
    assert any(r["run_id"] == rec["run_id"] for r in listed)


def test_mark_started_and_duration(rs: RunStore) -> None:
    rec = rs.create_run({"cloud": "gcp", "case_id": "CASE-1"})
    run_id = rec["run_id"]
    assert rs.get_run(run_id)["started_at"] is None

    rs.mark_started(run_id)
    meta = rs.get_run(run_id)
    assert meta["status"] == "running"
    assert meta["started_at"] is not None

    # mark_started is idempotent — a re-run of the worker must not reset the clock.
    first_start = meta["started_at"]
    rs.mark_started(run_id)
    assert rs.get_run(run_id)["started_at"] == first_start

    final = rs.finalize(run_id, status="failed", error="boom")
    assert final["status"] == "failed"
    assert final["finished_at"] is not None
    assert isinstance(final["duration_ms"], int) and final["duration_ms"] >= 0


def test_finalize_without_start_still_has_duration(rs: RunStore) -> None:
    # A run that fails before mark_started falls back to created_at, so duration is still present.
    rec = rs.create_run({"cloud": "gcp", "case_id": "CASE-1"})
    final = rs.finalize(rec["run_id"], status="failed", error="dns")
    assert isinstance(final["duration_ms"], int) and final["duration_ms"] >= 0


def test_matrix_and_finalize(rs: RunStore) -> None:
    rec = rs.create_run({"cloud": "aws", "case_id": "CASE-1"})
    run_id = rec["run_id"]
    rs.update_matrix(
        run_id,
        {
            "collectors": [{"name": "cloudtrail", "status": "pass", "records": 1}],
            "complete": 1,
            "total": 1,
        },
    )
    matrix = rs.get_matrix(run_id)
    assert matrix["complete"] == 1
    rs.append_event(run_id, {"type": "start", "collector": "cloudtrail"})
    events = rs.read_events(run_id)
    assert len(events) == 1
    rs.finalize(run_id, status="completed", extra={"package": {"path": "/tmp/pkg"}})
    meta = rs.get_run(run_id)
    assert meta["status"] == "completed"
    assert meta["package"]["path"] == "/tmp/pkg"


def test_missing_run_raises(rs: RunStore) -> None:
    with pytest.raises(RunNotFound):
        rs.get_run("no-such-run")


def test_request_cancel_moves_to_cancelling_with_reasons(rs: RunStore) -> None:
    rec = rs.create_run({"cloud": "aws", "case_id": "CASE-1", "status": "running"})
    run_id = rec["run_id"]
    rs.update_matrix(
        run_id,
        {
            "collectors": [
                {"name": "cloudtrail", "status": "running", "live_msg": "collecting…"},
                {"name": "iam", "status": "pending"},
                {"name": "s3", "status": "pass", "records": 5},
            ],
            "complete": 1,
            "total": 3,
        },
    )
    meta = rs.request_cancel(run_id)

    # Non-terminal transition — worker still owns finalization.
    assert meta["status"] == "cancelling"
    assert meta["cancel_requested"] is True
    assert "finished_at" not in meta or meta["finished_at"] is None

    matrix = rs.get_matrix(run_id)
    rows = {r["name"]: r for r in matrix["collectors"]}
    assert rows["cloudtrail"]["status"] == "fail"
    assert rows["cloudtrail"]["detail"] == "Cancelled while collecting"
    assert rows["cloudtrail"]["live_msg"] == ""
    assert rows["iam"]["status"] == "fail"
    assert rows["iam"]["detail"] == "Cancelled before start"
    assert rows["s3"]["status"] == "pass"  # terminal row untouched
    assert matrix["status"] == "cancelling"
    assert matrix["complete"] == 3
    assert any(e.get("type") == "cancelling" for e in rs.read_events(run_id))


def test_request_cancel_keeps_terminal_status(rs: RunStore) -> None:
    rec = rs.create_run({"cloud": "aws", "case_id": "CASE-1", "status": "completed"})
    run_id = rec["run_id"]
    meta = rs.request_cancel(run_id)
    # A finished run keeps its terminal status; only the flag is set.
    assert meta["status"] == "completed"
    assert meta["cancel_requested"] is True
