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
    import app.run_store as rs_mod

    store = RunStore(runs)
    rs_mod.run_store = store
    main_mod.run_store = store
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
