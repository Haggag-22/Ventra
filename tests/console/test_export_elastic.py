"""Backend tests for Elastic export (Track D4a)."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))
sys.path.insert(0, str(REPO / "console" / "backend"))

from generate_demo_case import generate  # noqa: E402

from app.rbac import CAPABILITIES, Role  # noqa: E402
from app.store import store  # noqa: E402
from ventra_ingester.exporters.elastic_ndjson import export_elastic_ndjson  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


@pytest.fixture(scope="module")
def ingested_case(tmp_path_factory) -> str:
    out = tmp_path_factory.mktemp("pkg")
    case_root = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-EXPORT-API")
    result = ingest_package(pkg, case_root)
    store.root = case_root
    return result.case_id


def test_export_report_capability_roles() -> None:
    allowed = CAPABILITIES["export_report"]
    assert Role.INVESTIGATOR in allowed
    assert Role.ANALYST in allowed
    assert Role.DATA_CUSTODIAN in allowed
    assert Role.RESPONDER not in allowed


def test_export_elastic_zip_bundle(ingested_case) -> None:
    case_id = ingested_case
    case_dir = store.case_dir(case_id)
    with tempfile.TemporaryDirectory(prefix="ventra-export-test-") as tmp:
        out_dir = Path(tmp) / "export"
        export_elastic_ndjson(case_dir, out_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(out_dir.rglob("*")):
                if path.is_file():
                    zf.write(path, arcname=path.relative_to(out_dir).as_posix())
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            names = zf.namelist()
            assert "export-manifest.json" in names
            assert any(n.endswith(".ndjson") for n in names)
            manifest = json.loads(zf.read("export-manifest.json"))
            assert manifest["case_id"] == case_id
            assert manifest["total_events"] > 0
