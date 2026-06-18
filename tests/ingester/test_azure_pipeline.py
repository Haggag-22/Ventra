"""End-to-end ingester test: generate an Azure demo package, ingest it, assert the case store."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb
import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_azure_demo_case import generate  # noqa: E402

from ventra_ingester.package import EvidencePackage  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402
from ventra_ingester.verify import verify_package  # noqa: E402


@pytest.fixture(scope="module")
def azure_demo_case(tmp_path_factory) -> tuple[Path, Path]:
    out = tmp_path_factory.mktemp("pkg")
    store = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-TEST-AZ-PIPE")
    result = ingest_package(pkg, store)
    return store / result.case_id, pkg


def test_integrity_all_hashes_match(azure_demo_case) -> None:
    _, pkg_path = azure_demo_case
    report = verify_package(EvidencePackage(pkg_path))
    assert report.overall in ("green", "amber")
    bad = [c.name for c in report.checks if not c.matched]
    assert bad == [], f"Hash mismatches: {bad}"


def test_case_store_built(azure_demo_case) -> None:
    case_dir, _ = azure_demo_case
    manifest = json.loads((case_dir / "manifest.json").read_text())
    assert manifest["cloud"] == "azure"
    for f in ("manifest.json", "integrity.json", "summary.json", "events.parquet"):
        assert (case_dir / f).is_file(), f"missing {f}"
    assert (case_dir / "inventory" / "entra_directory.json").is_file()
    assert (case_dir / "inventory" / "subscription.json").is_file()


def test_azure_attack_story_present(azure_demo_case) -> None:
    case_dir, _ = azure_demo_case
    con = duckdb.connect()
    path = str(case_dir / "events.parquet")
    total = con.execute(f"SELECT count(*) FROM '{path}'").fetchone()[0]
    assert total > 50

    signin = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='entra_signin' "
        "AND source_ip='203.0.113.66'"
    ).fetchone()[0]
    assert signin >= 2

    defender = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='defender'"
    ).fetchone()[0]
    assert defender >= 3

    exfil = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='vnet_flow' "
        "AND dest_ip='185.220.101.45'"
    ).fetchone()[0]
    assert exfil >= 5

    mail = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='unified_audit' "
        "AND event_action='MailItemsAccessed'"
    ).fetchone()[0]
    assert mail >= 1

    mail_search = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='unified_audit_search' "
        "AND event_action='MailItemsAccessed'"
    ).fetchone()[0]
    assert mail_search >= 1

    la = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='app_gateway' "
        "AND source_ip='203.0.113.66'"
    ).fetchone()[0]
    assert la >= 1

    oauth = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='oauth_consent'"
    ).fetchone()[0]
    assert oauth >= 1


def test_summary_reflects_azure_collection_gaps(azure_demo_case) -> None:
    case_dir, _ = azure_demo_case
    summary = json.loads((case_dir / "summary.json").read_text())
    gap_names = {g["name"] for g in summary["collection"]["gaps"]}
    assert "nsg_flow" in gap_names
    assert "dns" in gap_names or "key_vault" in gap_names
