"""End-to-end ingester test: generate a GCP demo package, ingest it, assert the case store."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb
import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_gcp_demo_case import generate  # noqa: E402

from ventra_ingester.package import EvidencePackage  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402
from ventra_ingester.verify import verify_package  # noqa: E402


@pytest.fixture(scope="module")
def gcp_demo_case(tmp_path_factory) -> tuple[Path, Path]:
    out = tmp_path_factory.mktemp("pkg")
    store = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-TEST-GCP-PIPE")
    result = ingest_package(pkg, store)
    return store / result.case_id, pkg


def test_integrity_all_hashes_match(gcp_demo_case) -> None:
    _, pkg_path = gcp_demo_case
    report = verify_package(EvidencePackage(pkg_path))
    assert report.overall in ("green", "amber")
    bad = [c.name for c in report.checks if not c.matched]
    assert bad == [], f"Hash mismatches: {bad}"


def test_case_store_built(gcp_demo_case) -> None:
    case_dir, _ = gcp_demo_case
    manifest = json.loads((case_dir / "manifest.json").read_text())
    assert manifest["cloud"] == "gcp"
    for f in ("manifest.json", "integrity.json", "summary.json", "events.parquet"):
        assert (case_dir / f).is_file(), f"missing {f}"
    assert (case_dir / "inventory" / "iam_policy.json").is_file()
    assert (case_dir / "inventory" / "project.json").is_file()


def test_manifest_records_artifact_provenance(gcp_demo_case) -> None:
    """Track A: the manifest carries artifacts[] with name + version for each collector."""
    case_dir, _ = gcp_demo_case
    manifest = json.loads((case_dir / "manifest.json").read_text())
    artifacts = manifest.get("artifacts")
    assert artifacts, "manifest is missing artifacts[] provenance"
    by_collector = {a["collector"]: a for a in artifacts}
    assert "cloud_audit_admin" in by_collector
    assert "scc_findings" in by_collector
    for a in artifacts:
        assert a["name"] and a["version"], f"artifact missing name/version: {a}"
        assert a["version"].count(".") == 2, f"non-semver version: {a}"


def test_gcp_attack_story_present(gcp_demo_case) -> None:
    case_dir, _ = gcp_demo_case
    con = duckdb.connect()
    path = str(case_dir / "events.parquet")
    total = con.execute(f"SELECT count(*) FROM '{path}'").fetchone()[0]
    assert total > 40

    # Every event is attributed to GCP — no cross-cloud normalizer bleed.
    providers = {r[0] for r in con.execute(f"SELECT DISTINCT cloud_provider FROM '{path}'").fetchall()}
    assert providers == {"gcp"}, providers

    # gcp_audit normalizer: SetIamPolicy from the attacker IP (privilege escalation).
    setiam = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='cloud_audit_admin' "
        "AND event_action LIKE '%SetIamPolicy%' AND source_ip='203.0.113.66'"
    ).fetchone()[0]
    assert setiam >= 1

    # gcp_audit normalizer: data-access object reads.
    reads = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='cloud_audit_data' "
        "AND event_action='storage.objects.get'"
    ).fetchone()[0]
    assert reads >= 10

    # gcp_findings normalizer: SCC findings carry the finding kind.
    findings = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='scc_findings' AND event_kind='finding'"
    ).fetchone()[0]
    assert findings >= 3

    # vpc_flow normalizer (GCP shape): egress to the exfil IP.
    exfil = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='vpc_flow' AND dest_ip='185.220.101.45'"
    ).fetchone()[0]
    assert exfil >= 5

    # login_events normalizer: the foreign-IP session is captured.
    login = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='login_events' "
        "AND source_ip='203.0.113.66'"
    ).fetchone()[0]
    assert login >= 1


def test_summary_reflects_gcp_collection_gaps(gcp_demo_case) -> None:
    case_dir, _ = gcp_demo_case
    summary = json.loads((case_dir / "summary.json").read_text())
    gap_names = {g["name"] for g in summary["collection"]["gaps"]}
    assert "workspace_audit" in gap_names
