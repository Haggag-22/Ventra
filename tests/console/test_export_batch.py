"""Backend tests for the batch export (/api/cases/export) and /api/cases/exportable."""

from __future__ import annotations

import io
import json
import sys
import time
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))
sys.path.insert(0, str(REPO / "console" / "backend"))

from fastapi.testclient import TestClient  # noqa: E402
from generate_demo_case import generate  # noqa: E402

from app.main import app  # noqa: E402
from app.rbac import CAPABILITIES, Role  # noqa: E402
from app.store import store  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


@pytest.fixture(scope="module")
def case_ids(tmp_path_factory) -> list[str]:
    """Two ingested cases sharing one case store, for batch export tests."""
    out = tmp_path_factory.mktemp("pkg")
    case_root = tmp_path_factory.mktemp("cases")
    ids = []
    for cid in ("CASE-EXPORT-BATCH-1", "CASE-EXPORT-BATCH-2"):
        pkg = generate(out / cid, cid)
        result = ingest_package(pkg, case_root)
        ids.append(result.case_id)
    store.root = case_root
    return ids


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _role_without_export() -> Role:
    allowed = CAPABILITIES["export_report"]
    for role in Role:
        if role not in allowed:
            return role
    raise AssertionError("every role has export_report — RBAC test can't distinguish")


def _run_export(client: TestClient, payload: dict, *, role: str = "investigator"):
    """POST an export job, wait for it to finish, and return the download response.

    Export is now a job (POST returns a job id; poll status; then download) so a large,
    slow build no longer blocks the HTTP request until completion.
    """
    start = client.post("/api/cases/export", json=payload, headers={"X-Ventra-Role": role})
    if start.status_code != 200:
        return start
    job_id = start.json()["job_id"]
    for _ in range(400):
        status = client.get(f"/api/cases/export/{job_id}", headers={"X-Ventra-Role": role}).json()
        if status["status"] == "ready":
            break
        if status["status"] == "error":
            raise AssertionError(f"export job failed: {status.get('error')}")
        time.sleep(0.05)
    else:
        raise AssertionError("export job did not finish in time")
    return client.get(f"/api/cases/export/{job_id}/download", headers={"X-Ventra-Role": role})


def test_exportable_cases_lists_ingested_cases(client: TestClient, case_ids: list[str]) -> None:
    res = client.get("/api/cases/exportable", headers={"X-Ventra-Role": "investigator"})
    assert res.status_code == 200
    rows = {r["case_id"]: r for r in res.json()["cases"]}
    for cid in case_ids:
        assert cid in rows
        row = rows[cid]
        assert row["event_count"] > 0
        assert row["date_range"]["first"]
        assert row["integrity"] in ("green", "amber", "red", "unknown")
        assert row["sources"]
        assert isinstance(row.get("by_source"), dict)
        assert set(row["by_source"]) == set(row["sources"])
        assert isinstance(row["storage_bytes"], int)
        assert row["storage_bytes"] > 0


def test_exportable_cases_requires_export_report_capability(client: TestClient, case_ids: list[str]) -> None:
    role = _role_without_export()
    res = client.get("/api/cases/exportable", headers={"X-Ventra-Role": role.value})
    assert res.status_code == 403


def test_export_batch_single_case_matches_existing_shape(client: TestClient, case_ids: list[str]) -> None:
    res = _run_export(client, {"case_ids": [case_ids[0]], "target": "elastic"})
    assert res.status_code == 200
    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        names = zf.namelist()
        assert "export-manifest.json" in names
        assert any(n.endswith(".ndjson") for n in names)
        manifest = json.loads(zf.read("export-manifest.json"))
        assert manifest["case_id"] == case_ids[0]
        assert manifest["format"] == "elastic-ecs-ndjson"


def test_export_batch_multiple_cases_produces_per_case_subfolders(
    client: TestClient, case_ids: list[str]
) -> None:
    res = _run_export(client, {"case_ids": case_ids, "target": "ndjson"})
    assert res.status_code == 200
    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        names = zf.namelist()
        assert "export-manifest.json" in names
        combined = json.loads(zf.read("export-manifest.json"))
        assert combined["target"] == "ndjson"
        assert {c["case_id"] for c in combined["cases"]} == set(case_ids)
        assert combined["total_events"] == sum(c["total_events"] for c in combined["cases"])

        for cid in case_ids:
            assert f"{cid}/export-manifest.json" in names
            assert any(n.startswith(f"{cid}/") and n.endswith(".ndjson") for n in names)
            per_case_manifest = json.loads(zf.read(f"{cid}/export-manifest.json"))
            assert per_case_manifest["case_id"] == cid


def test_export_batch_respects_source_and_date_filters(client: TestClient, case_ids: list[str]) -> None:
    exportable = client.get("/api/cases/exportable", headers={"X-Ventra-Role": "investigator"}).json()[
        "cases"
    ]
    row = next(r for r in exportable if r["case_id"] == case_ids[0])
    one_source = row["sources"][0]

    res = _run_export(client, {"case_ids": [case_ids[0]], "target": "ndjson", "sources": [one_source]})
    assert res.status_code == 200
    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        manifest = json.loads(zf.read("export-manifest.json"))
        assert manifest["sources"] == [one_source]

    res_future = _run_export(
        client,
        {"case_ids": [case_ids[0]], "target": "ndjson", "since": "2999-01-01T00:00:00Z"},
    )
    assert res_future.status_code == 200
    with zipfile.ZipFile(io.BytesIO(res_future.content)) as zf:
        manifest = json.loads(zf.read("export-manifest.json"))
        assert manifest["total_events"] == 0


def test_export_batch_requires_export_report_capability(client: TestClient, case_ids: list[str]) -> None:
    role = _role_without_export()
    res = client.post(
        "/api/cases/export",
        json={"case_ids": case_ids, "target": "elastic"},
        headers={"X-Ventra-Role": role.value},
    )
    assert res.status_code == 403


def test_export_batch_empty_case_ids_is_400(client: TestClient, case_ids: list[str]) -> None:
    res = client.post(
        "/api/cases/export",
        json={"case_ids": [], "target": "elastic"},
        headers={"X-Ventra-Role": "investigator"},
    )
    assert res.status_code == 400


def test_export_batch_unknown_case_id_is_404(client: TestClient, case_ids: list[str]) -> None:
    res = client.post(
        "/api/cases/export",
        json={"case_ids": ["CASE-DOES-NOT-EXIST"], "target": "elastic"},
        headers={"X-Ventra-Role": "investigator"},
    )
    assert res.status_code == 404


def test_export_settings_reports_drop_zone(client: TestClient, monkeypatch, tmp_path: Path) -> None:
    from app import config as config_mod

    monkeypatch.setattr(config_mod.settings, "export_drop_dir", None)
    res = client.get("/api/cases/export/settings", headers={"X-Ventra-Role": "investigator"})
    assert res.status_code == 200
    assert res.json()["drop_zone"] == {"configured": False, "path": None}

    drop = tmp_path / "siem-drop"
    drop.mkdir()
    monkeypatch.setattr(config_mod.settings, "export_drop_dir", drop)
    res2 = client.get("/api/cases/export/settings", headers={"X-Ventra-Role": "investigator"})
    assert res2.status_code == 200
    body = res2.json()["drop_zone"]
    assert body["configured"] is True
    assert body["path"] == str(drop)


def test_export_drop_zone_requires_config(client: TestClient, case_ids: list[str], monkeypatch) -> None:
    from app import config as config_mod

    monkeypatch.setattr(config_mod.settings, "export_drop_dir", None)
    res = client.post(
        "/api/cases/export",
        json={"case_ids": [case_ids[0]], "target": "elastic", "delivery": "drop_zone"},
        headers={"X-Ventra-Role": "investigator"},
    )
    assert res.status_code == 400
    assert "VENTRA_EXPORT_DROP_DIR" in res.json()["detail"]


def test_export_drop_zone_writes_ndjson(
    client: TestClient, case_ids: list[str], monkeypatch, tmp_path: Path
) -> None:
    from app import config as config_mod

    drop = tmp_path / "siem-drop"
    drop.mkdir()
    monkeypatch.setattr(config_mod.settings, "export_drop_dir", drop)

    start = client.post(
        "/api/cases/export",
        json={"case_ids": [case_ids[0]], "target": "elastic", "delivery": "drop_zone"},
        headers={"X-Ventra-Role": "investigator"},
    )
    assert start.status_code == 200
    assert start.json()["delivery"] == "drop_zone"
    job_id = start.json()["job_id"]

    drop_path = None
    for _ in range(400):
        status = client.get(f"/api/cases/export/{job_id}", headers={"X-Ventra-Role": "investigator"}).json()
        if status["status"] == "ready":
            drop_path = status["drop_path"]
            assert status["delivery"] == "drop_zone"
            assert status["total_events"] is not None
            break
        if status["status"] == "error":
            raise AssertionError(f"export job failed: {status.get('error')}")
        time.sleep(0.05)
    else:
        raise AssertionError("export job did not finish in time")

    assert drop_path
    out = Path(drop_path)
    assert out.is_dir()
    assert out.parent == drop
    assert (out / "export-manifest.json").is_file()
    assert any(out.glob("*.ndjson"))
    # No leftover partial staging dirs
    assert not any(drop.glob(".partial-*"))

    # Drop-zone jobs have no zip download
    dl = client.get(f"/api/cases/export/{job_id}/download", headers={"X-Ventra-Role": "investigator"})
    assert dl.status_code == 400


def test_export_drop_zone_batch_layout(
    client: TestClient, case_ids: list[str], monkeypatch, tmp_path: Path
) -> None:
    from app import config as config_mod

    drop = tmp_path / "siem-drop"
    drop.mkdir()
    monkeypatch.setattr(config_mod.settings, "export_drop_dir", drop)

    start = client.post(
        "/api/cases/export",
        json={"case_ids": case_ids, "target": "ndjson", "delivery": "drop_zone"},
        headers={"X-Ventra-Role": "investigator"},
    )
    assert start.status_code == 200
    job_id = start.json()["job_id"]

    drop_path = None
    for _ in range(400):
        status = client.get(f"/api/cases/export/{job_id}", headers={"X-Ventra-Role": "investigator"}).json()
        if status["status"] == "ready":
            drop_path = status["drop_path"]
            break
        if status["status"] == "error":
            raise AssertionError(f"export job failed: {status.get('error')}")
        time.sleep(0.05)
    else:
        raise AssertionError("export job did not finish in time")

    out = Path(drop_path)
    assert (out / "export-manifest.json").is_file()
    for cid in case_ids:
        assert (out / cid / "export-manifest.json").is_file()
        assert any((out / cid).glob("*.ndjson"))


def test_export_job_can_be_cancelled(client: TestClient, case_ids: list[str]) -> None:
    start = client.post(
        "/api/cases/export",
        json={"case_ids": [case_ids[0]], "target": "elastic"},
        headers={"X-Ventra-Role": "investigator"},
    )
    assert start.status_code == 200
    job_id = start.json()["job_id"]

    cancel = client.post(
        f"/api/cases/export/{job_id}/cancel",
        headers={"X-Ventra-Role": "investigator"},
    )
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelled"

    # Poll should report cancelled; download must not succeed.
    status = client.get(f"/api/cases/export/{job_id}", headers={"X-Ventra-Role": "investigator"}).json()
    assert status["status"] == "cancelled"
    dl = client.get(f"/api/cases/export/{job_id}/download", headers={"X-Ventra-Role": "investigator"})
    assert dl.status_code == 409
