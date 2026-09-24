"""GCP coverage for the three panel-query functions that had hardcoded AWS/Azure sources:
network_overview, web_dns_overview, data_access_overview. Ingests the GCP demo case and
confirms each panel actually populates for GCP ventra_source values — including rows that
only exist because the ingester's content-based reclassification (gcp_audit.py) restores
subset collectors' specific ventra_source from the shared cloud_audit_data/load_balancer
tables.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))
sys.path.insert(0, str(REPO / "console" / "backend"))

from generate_gcp_demo_case import generate  # noqa: E402

from app.store import CaseStore  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


@pytest.fixture(scope="module")
def gcp_store_case(tmp_path_factory) -> tuple[CaseStore, str]:
    out = tmp_path_factory.mktemp("pkg")
    root = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-TEST-STORE-GCP")
    result = ingest_package(pkg, root)
    return CaseStore(root=root), result.case_id


def test_network_overview_populates_for_gcp(gcp_store_case) -> None:
    store, case_id = gcp_store_case
    net = store.network_overview(case_id)
    assert net["totals"]["flows"] > 0
    # The large egress burst to EXFIL_IP is public traffic. Byte-independent signal —
    # GCP's vpc_flow normalizer doesn't currently populate dest_bytes (pre-existing,
    # separate gap in ingester/ventra_ingester/normalizer/sources/network.py, out of
    # scope here), so public_bytes/egress_public byte sums stay 0 for GCP for now.
    assert net["totals"]["external_dests"] > 0


def test_web_dns_overview_populates_for_gcp(gcp_store_case) -> None:
    store, case_id = gcp_store_case
    web = store.web_dns_overview(case_id)
    # Plain LB requests + the CDN cache-hit rows all count as "edge" — the Armor-blocked
    # probe is correctly excluded (reclassified to ventra_source='cloud_armor', a WAF hit,
    # not an edge request; this is the dedup/reclassification behavior working as intended).
    assert web["edge"]["totals"]["requests"] >= 8
    assert web["edge"]["status_classes"], "status classes derived from the → NNN message shape"
    assert any("/product/" in p["target"] for p in web["edge"]["top_paths"])
    # Cloud Armor's blocked probe shows up as a WAF hit (ventra_source='cloud_armor').
    assert web["waf"]["totals"]["blocked"] > 0


def test_data_access_overview_populates_for_gcp(gcp_store_case) -> None:
    store, case_id = gcp_store_case
    da = store.data_access_overview(case_id)
    assert da["totals"]["events"] > 0
    # GCS object reads (reclassified from cloud_audit_data to storage_access at ingest).
    assert any("customer-export" in o["resource_id"] for o in da["top_objects"])


def test_data_access_scope_excludes_generic_audit_admin(gcp_store_case) -> None:
    """DATA_ACCESS_SCOPE must not pull in cloud_audit_admin (SetIamPolicy etc.) — only the
    reclassified data-access subset streams."""
    store, case_id = gcp_store_case
    con = store._connect()
    path = store._events_path(case_id)
    try:
        events = store._events_table(con, path)
        from app.store import DATA_ACCESS_SCOPE

        leaked = con.execute(
            f"SELECT count(*) FROM {events} WHERE {DATA_ACCESS_SCOPE} AND ventra_source='cloud_audit_admin'",
            [path],
        ).fetchone()[0]
        assert leaked == 0
    finally:
        con.close()
