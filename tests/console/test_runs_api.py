"""Runs API integration tests (mocked collection)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "backend"))

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.run_store import RunStore  # noqa: E402


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    runs = tmp_path / "runs"
    cfg = tmp_path / "config"
    runs.mkdir()
    cfg.mkdir()
    monkeypatch.setattr(settings, "runs_dir", runs)
    monkeypatch.setattr(settings, "config_dir", cfg)
    import app.config_store as cs_mod
    import app.main as main_mod
    import app.run_service as run_service_mod
    import app.run_store as rs_mod

    store = RunStore(runs)
    rs_mod.run_store = store
    main_mod.run_store = store
    run_service_mod.run_store = store
    cs_mod.config_store = cs_mod.ConfigStore(cfg)
    main_mod.config_store = cs_mod.config_store
    return TestClient(app)


def test_list_runs_empty(client: TestClient) -> None:
    res = client.get("/api/runs", headers={"X-Ventra-Role": "investigator"})
    assert res.status_code == 200
    assert res.json()["runs"] == []


def test_create_run_returns_id(client: TestClient) -> None:
    body = {
        "cloud": "aws",
        "case_id": "CASE-TEST-RUN",
        "artifacts": ["account"],
        "auto_ingest": False,
    }
    with patch("app.run_service._execute_run"):
        res = client.post("/api/runs", json=body, headers={"X-Ventra-Role": "responder"})
    assert res.status_code == 200
    data = res.json()
    assert data["run_id"]


def test_matrix_shape(client: TestClient) -> None:
    import app.run_store as rs_mod

    rec = rs_mod.run_store.create_run({"cloud": "aws", "case_id": "CASE-1"})
    run_id = rec["run_id"]
    rs_mod.run_store.update_matrix(
        run_id,
        {
            "collectors": [{"name": "cloudtrail", "status": "running", "detail": "collecting"}],
            "complete": 0,
            "total": 1,
        },
    )
    res = client.get(f"/api/runs/{run_id}/matrix", headers={"X-Ventra-Role": "investigator"})
    assert res.status_code == 200
    data = res.json()
    assert data["rows"][0]["name"] == "cloudtrail"
    assert data["total"] == 1


def test_cancel_inactive_run_finalizes_cancelled(client: TestClient) -> None:
    """Cancelling a run with no live worker finalizes it to cancelled, in sync."""
    import app.run_store as rs_mod

    rec = rs_mod.run_store.create_run({"cloud": "aws", "case_id": "CASE-1", "status": "running"})
    run_id = rec["run_id"]
    rs_mod.run_store.update_matrix(
        run_id,
        {
            "collectors": [
                {"name": "cloudtrail", "status": "running", "live_msg": "collecting…"},
                {"name": "iam", "status": "pending"},
            ],
            "complete": 0,
            "total": 2,
        },
    )

    res = client.post(f"/api/runs/{run_id}/cancel", headers={"X-Ventra-Role": "responder"})
    assert res.status_code == 200
    # Cancel always finalizes immediately — UI never waits on a worker.
    assert res.json()["status"] == "cancelled"

    matrix = client.get(f"/api/runs/{run_id}/matrix", headers={"X-Ventra-Role": "investigator"}).json()
    rows = {r["name"]: r for r in matrix["rows"]}
    assert rows["cloudtrail"]["status"] == "fail"
    assert rows["cloudtrail"]["live_msg"] == ""
    assert rows["iam"]["status"] == "fail"
    assert matrix["status"] == "cancelled"


def test_list_runs_reclaims_stuck_cancelling(client: TestClient) -> None:
    """Orphaned cancelling runs (dead worker) are finalized when listing."""
    import app.run_store as rs_mod

    rec = rs_mod.run_store.create_run({"cloud": "aws", "case_id": "CASE-1", "status": "running"})
    run_id = rec["run_id"]
    rs_mod.run_store.request_cancel(run_id)
    assert rs_mod.run_store.get_run(run_id)["status"] == "cancelling"

    res = client.get("/api/runs", headers={"X-Ventra-Role": "investigator"})
    assert res.status_code == 200
    listed = {r["run_id"]: r for r in res.json()["runs"]}
    assert listed[run_id]["status"] == "cancelled"


def test_cancel_terminal_run_is_noop(client: TestClient) -> None:
    import app.run_store as rs_mod

    rec = rs_mod.run_store.create_run({"cloud": "aws", "case_id": "CASE-1"})
    run_id = rec["run_id"]
    rs_mod.run_store.finalize(run_id, status="completed")
    res = client.post(f"/api/runs/{run_id}/cancel", headers={"X-Ventra-Role": "responder"})
    assert res.status_code == 200
    assert res.json()["status"] == "completed"


def test_case_overview(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sys.path.insert(0, str(REPO / "tests" / "fixtures"))
    from generate_demo_case import generate  # noqa: E402

    case_root = tmp_path / "cases"
    pkg = generate(tmp_path / "pkg", "CASE-OVERVIEW-API")
    from ventra_ingester.pipeline import ingest_package  # noqa: E402

    ingest_package(pkg, case_root)
    monkeypatch.setattr(settings, "case_store", case_root)
    import app.main as main_mod
    import app.store as store_mod

    store_mod.store = store_mod.CaseStore(root=case_root)
    main_mod.store = store_mod.store

    res = client.get("/api/cases/CASE-OVERVIEW-API/overview", headers={"X-Ventra-Role": "investigator"})
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == "CASE-OVERVIEW-API"
    assert "coverage_pct" in data
    assert "gaps" in data
    assert "findings_by_severity" in data
