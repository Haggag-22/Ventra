"""End-to-end ingester test: generate a demo package, ingest it, assert the case store.

This exercises the full verify -> parse -> normalize -> enrich -> load path against the same
synthetic attack scenario the console demos, then queries the resulting Parquet with DuckDB.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb
import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_demo_case import generate  # noqa: E402

from ventra_ingester.package import EvidencePackage  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402
from ventra_ingester.verify import verify_package  # noqa: E402


@pytest.fixture(scope="module")
def demo_case(tmp_path_factory) -> tuple[Path, Path]:
    out = tmp_path_factory.mktemp("pkg")
    store = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-TEST-PIPE")
    result = ingest_package(pkg, store)
    return store / result.case_id, pkg


def test_integrity_all_hashes_match(demo_case) -> None:
    _, pkg_path = demo_case
    report = verify_package(EvidencePackage(pkg_path))
    # Demo seals with sha256-stamp, so overall is amber but every source hash must match.
    assert report.overall in ("green", "amber")
    bad = [c.name for c in report.checks if not c.matched]
    assert bad == [], f"Hash mismatches: {bad}"


def test_case_store_built(demo_case) -> None:
    case_dir, _ = demo_case
    for f in ("manifest.json", "integrity.json", "summary.json", "events.parquet"):
        assert (case_dir / f).is_file(), f"missing {f}"
    assert (case_dir / "inventory" / "iam.json").is_file()


def test_events_normalized_and_queryable(demo_case) -> None:
    case_dir, _ = demo_case
    con = duckdb.connect()
    path = str(case_dir / "events.parquet")
    total = con.execute(f"SELECT count(*) FROM '{path}'").fetchone()[0]
    assert total > 100

    # The attack story must be present and correctly classified.
    crit = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE event_severity='critical'"
    ).fetchone()[0]
    assert crit >= 2  # StopLogging + GuardDuty CloudTrailLoggingDisabled etc.

    stop = con.execute(
        f"SELECT event_severity FROM '{path}' WHERE event_action='StopLogging'"
    ).fetchone()
    assert stop and stop[0] == "critical"

    # Pivot dimension: the attacker IP should tie many events together.
    n = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE related_ip LIKE '%203.0.113.66%'"
    ).fetchone()[0]
    assert n > 10


def test_summary_reflects_collection_gap(demo_case) -> None:
    case_dir, _ = demo_case
    summary = json.loads((case_dir / "summary.json").read_text())
    gap_names = {g["name"] for g in summary["collection"]["gaps"]}
    # The demo deliberately leaves several sources unconfigured (recorded via log_posture).
    assert "eks_audit" in gap_names
    assert "cloudfront" in gap_names


def test_access_and_dns_logs_normalized(demo_case) -> None:
    """ELB/ALB and Route53 Resolver records flow through their normalizers into the store."""
    case_dir, _ = demo_case
    con = duckdb.connect()
    path = str(case_dir / "events.parquet")

    alb = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='elb_alb'"
    ).fetchone()[0]
    assert alb > 20

    # The attacker's admin-panel probe must be present and pivotable by IP.
    probe = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='elb_alb' "
        "AND source_ip='203.0.113.66' AND message LIKE '%/admin/login%'"
    ).fetchone()[0]
    assert probe >= 1

    dns = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='route53_resolver'"
    ).fetchone()[0]
    assert dns > 20

    nxdomain = con.execute(
        f"SELECT count(*) FROM '{path}' WHERE ventra_source='route53_resolver' "
        "AND event_outcome='failure'"
    ).fetchone()[0]
    assert nxdomain >= 8  # the DGA burst


def test_assume_role_events_folded_into_cloudtrail(demo_case) -> None:
    """No separate STS source: AssumeRole events come from cloudtrail, role-targeted."""
    case_dir, _ = demo_case
    con = duckdb.connect()
    path = str(case_dir / "events.parquet")

    # The phantom 'sts' source is gone entirely.
    assert (
        con.execute(f"SELECT count(*) FROM '{path}' WHERE ventra_source='sts'").fetchone()[0]
        == 0
    )

    rows = con.execute(
        f"SELECT ventra_source, resource_type, resource_arn FROM '{path}' "
        "WHERE event_action='AssumeRole'"
    ).fetchall()
    assert rows, "expected AssumeRole events in the cloudtrail source"
    assert all(src == "cloudtrail" for src, _, _ in rows)
    assert all(rtype == "iam-role" for _, rtype, _ in rows)  # graph targets the role
    assert all(":role/" in (arn or "") for _, _, arn in rows)
