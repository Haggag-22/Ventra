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
