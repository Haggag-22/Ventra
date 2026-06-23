"""Console backend query-layer tests.

Ingests the synthetic demo case the console ships with, then exercises ``CaseStore`` — the
hand-built, allow-list-guarded DuckDB query layer the whole console reads through. The most
important assertion here is that filter keys and sort columns outside the allow-lists can never
reach the SQL (injection safety); the rest lock the panel queries against the demo scenario.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))
sys.path.insert(0, str(REPO / "console" / "backend"))

from generate_demo_case import generate  # noqa: E402

from app.store import CaseNotFound, CaseStore, EventQuery, _vpc_ids_from_flow_config, network_vpc_filter_clause  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


@pytest.fixture(scope="module")
def store_case(tmp_path_factory) -> tuple[CaseStore, str]:
    out = tmp_path_factory.mktemp("pkg")
    root = tmp_path_factory.mktemp("cases")
    pkg = generate(out, "CASE-TEST-STORE")
    result = ingest_package(pkg, root)
    return CaseStore(root=root), result.case_id


# -- discovery / sidecars ----------------------------------------------------------------

def test_list_cases_and_summary(store_case) -> None:
    store, case_id = store_case
    cases = store.list_cases()
    assert any(c["case_id"] == case_id for c in cases)

    summary = store.summary(case_id)
    assert summary["case_id"] == case_id
    assert summary["cloud"] == "aws"
    assert summary["totals"]["events"] > 100


def test_missing_case_raises(store_case) -> None:
    store, _ = store_case
    with pytest.raises(CaseNotFound):
        store.summary("no-such-case")


# -- events ------------------------------------------------------------------------------

def test_query_events_basic_paging(store_case) -> None:
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(limit=10))
    assert res["total"] > 100
    assert res["count"] == 10  # limit honored
    assert len(res["events"]) == 10
    # list/dict columns are decoded back from their JSON-string storage.
    assert isinstance(res["events"][0]["event_category"], list)


def test_severity_filter(store_case) -> None:
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(filters={"event_severity": "critical"}, limit=500))
    assert res["total"] >= 2  # StopLogging + GuardDuty CloudTrailLoggingDisabled, etc.
    assert all(e["event_severity"] == "critical" for e in res["events"])


def test_source_filter(store_case) -> None:
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(sources=["cloudtrail"], limit=50))
    assert res["total"] > 0
    assert {e["ventra_source"] for e in res["events"]} == {"cloudtrail"}


def test_kubernetes_audit_source_filter(store_case) -> None:
    """EKS audit events are queryable by ventra_source when present (demo case has none)."""
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(sources=["eks_audit"], limit=50))
    assert res["total"] >= 0
    assert all(e["ventra_source"] == "eks_audit" for e in res["events"])
    facets = store.facets(case_id, EventQuery(sources=["eks_audit"]))
    assert "event_action" in facets
    assert "event_severity" in facets


def test_free_text_search(store_case) -> None:
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(q="StopLogging", limit=50))
    assert res["total"] >= 1
    assert any(e["event_action"] == "StopLogging" for e in res["events"])


def test_non_allowlisted_filter_is_ignored(store_case) -> None:
    """A filter key outside FILTERABLE (or an injection attempt) must not reach the SQL."""
    store, case_id = store_case
    baseline = store.query_events(case_id, EventQuery(limit=1))["total"]
    attack = store.query_events(
        case_id,
        EventQuery(filters={"event_action; DROP TABLE x": "1' OR '1'='1"}, limit=1),
    )
    assert attack["total"] == baseline  # filter silently dropped, no error, no injection


def test_invalid_sort_falls_back(store_case) -> None:
    """An unknown sort column falls back to timestamp instead of being interpolated."""
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(sort="; DROP TABLE x", order="desc", limit=5))
    assert res["count"] == 5  # query ran safely


def test_severity_sort_ranks_not_alphabetical(store_case) -> None:
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(sort="event_severity", order="desc", limit=1))
    assert res["events"][0]["event_severity"] == "critical"


# -- aggregations ------------------------------------------------------------------------

def test_facets(store_case) -> None:
    store, case_id = store_case
    facets = store.facets(case_id, EventQuery())
    assert "ventra_source" in facets
    sources = {f["value"] for f in facets["ventra_source"]}
    assert "cloudtrail" in sources
    assert all(f["count"] > 0 for f in facets["ventra_source"])


def test_identity_role_graph(store_case) -> None:
    store, case_id = store_case
    graph = store.role_assumption_graph(case_id)
    assert graph["nodes"], "demo includes AssumeRole activity"
    assert graph["edges"]
    assert all("source" in e and "target" in e for e in graph["edges"])


def test_network_overview(store_case) -> None:
    store, case_id = store_case
    net = store.network_overview(case_id)
    assert net["case_totals"]["flows"] > 0
    assert net["case_totals"]["flows"] == net["totals"]["flows"]
    assert net["totals"]["flows"] > 0
    assert net["totals"]["rejects"] > 0
    # Exfil lens: large egress to a public IP is computed server-side.
    assert net["totals"]["public_bytes"] > 0
    assert net["egress_public"], "demo has egress to a public IP"
    assert all(":" not in e["dest_ip"] for e in net["egress_public"])
    # Recon hit risky ports (22/3389/445/23) — they appear in the port breakdown.
    ports = {p["port"] for p in net["top_ports"]}
    assert ports & {22, 3389, 445, 23}
    # Protocol field parsed from the raw flow record.
    assert any(p["protocol"] == "6" for p in net["protocols"])  # TCP


def test_network_vpcs_and_filter(store_case) -> None:
    store, case_id = store_case
    listed = store.network_vpcs(case_id)
    assert len(listed["vpcs"]) >= 2
    ids = {v["id"] for v in listed["vpcs"]}
    assert "vpc-0demo1234" in ids
    assert "vpc-0demo5678" in ids
    by_id = {v["id"]: v for v in listed["vpcs"]}
    assert by_id["vpc-0demo1234"]["name"] == "demo-primary-vpc"
    assert by_id["vpc-0demo5678"]["name"] == "demo-secondary-vpc"

    all_net = store.network_overview(case_id)
    primary = store.network_overview(case_id, vpc_id="vpc-0demo1234")
    secondary = store.network_overview(case_id, vpc_id="vpc-0demo5678")

    assert primary["totals"]["flows"] < all_net["totals"]["flows"]
    assert secondary["totals"]["flows"] < all_net["totals"]["flows"]
    assert primary["totals"]["public_bytes"] > 0  # exfil lives in primary VPC
    assert secondary["totals"]["public_bytes"] == 0

    events = store.query_events(
        case_id,
        EventQuery(sources=["vpc_flow"], vpcs=["vpc-0demo5678"], limit=500),
    )
    assert events["total"] == secondary["totals"]["flows"]
    assert events["total"] > 0


def test_vpc_ids_from_flow_config() -> None:
    ids = _vpc_ids_from_flow_config(
        {
            "vpcs": [{"VpcId": "vpc-aaa"}, {"VpcId": "vpc-bbb"}],
            "flow_logs": [
                {"ResourceId": "vpc-ccc", "FlowLogStatus": "ACTIVE"},
                {"ResourceId": "subnet-xyz", "FlowLogStatus": "ACTIVE"},
                {"ResourceId": "vpc-inactive", "FlowLogStatus": "INACTIVE"},
            ],
        }
    )
    assert ids == ["vpc-ccc"]


def test_network_vpc_filter_clause_sole_vpc_includes_untagged() -> None:
    clause, params = network_vpc_filter_clause(["vpc-only"], ["vpc-only"])
    assert "OR" in clause
    assert "''" in clause
    assert params == ["vpc-only"]

    clause2, params2 = network_vpc_filter_clause(["vpc-a"], ["vpc-a", "vpc-b"])
    assert "OR" not in clause2
    assert params2 == ["vpc-a"]


def test_network_sole_flow_vpc_filter(store_case, tmp_path) -> None:
    """Sole flow-log VPC filter matches tagged records and would include untagged ones."""
    store, case_id = store_case
    inv_path = store.case_dir(case_id) / "inventory" / "vpc_flow.json"
    inv_path.write_text(
        json.dumps(
            {
                "_config": {
                    "flow_logs": [
                        {
                            "ResourceId": "vpc-0demo1234",
                            "LogDestinationType": "s3",
                            "FlowLogStatus": "ACTIVE",
                        }
                    ],
                    "vpcs": [
                        {
                            "VpcId": "vpc-0demo1234",
                            "Tags": [{"Key": "Name", "Value": "demo-primary-vpc"}],
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    all_net = store.network_overview(case_id)
    sole_net = store.network_overview(case_id, vpc_id="vpc-0demo1234")
    assert sole_net["totals"]["flows"] > 0
    assert sole_net["totals"]["flows"] <= all_net["case_totals"]["flows"]

    events = store.query_events(
        case_id,
        EventQuery(sources=["vpc_flow"], vpcs=["vpc-0demo1234"], limit=5000),
    )
    assert events["total"] == sole_net["totals"]["flows"]

    listed = store.network_vpcs(case_id)
    assert [v["id"] for v in listed["vpcs"]] == ["vpc-0demo1234"]
    assert listed["vpcs"][0]["flows"] == sole_net["totals"]["flows"]


def test_network_vpcs_only_flow_log_vpcs(store_case, tmp_path) -> None:
    """Dropdown lists only VPCs with flow-log config, not the full inventory."""
    store, case_id = store_case
    inv_path = store.case_dir(case_id) / "inventory" / "vpc_flow.json"
    inv_path.write_text(
        json.dumps(
            {
                "_config": {
                    "flow_logs": [
                        {
                            "ResourceId": "vpc-realtest01",
                            "LogDestinationType": "s3",
                            "FlowLogStatus": "ACTIVE",
                        }
                    ],
                    "vpcs": [
                        {
                            "VpcId": "vpc-realtest01",
                            "Tags": [{"Key": "Name", "Value": "real-primary"}],
                        },
                        {
                            "VpcId": "vpc-realtest02",
                            "Tags": [{"Key": "Name", "Value": "no-flow-log"}],
                        },
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    listed = store.network_vpcs(case_id)
    assert [v["id"] for v in listed["vpcs"]] == ["vpc-realtest01"]
    assert listed["vpcs"][0]["name"] == "real-primary"
    ids = {v["id"] for v in listed["vpcs"]}
    assert "vpc-realtest02" not in ids
    assert "vpc-0demo1234" not in ids


def test_web_dns_overview(store_case) -> None:
    store, case_id = store_case
    web = store.web_dns_overview(case_id)
    # Edge (ALB) requests with an HTTP status breakdown and URL paths.
    assert web["edge"]["totals"]["requests"] > 0
    assert web["edge"]["status_classes"], "status classes derived from the log lines"
    assert any("/admin/login" in p["target"] for p in web["edge"]["top_paths"])
    # WAF blocked the attacker's SQLi/XSS.
    assert web["waf"]["totals"]["blocked"] > 0
    # DNS: NXDOMAIN burst shows as failures; A is the dominant qtype.
    assert web["dns"]["totals"]["failures"] > 0
    assert any(t["qtype"] == "A" for t in web["dns"]["qtypes"])


def test_data_access_overview(store_case) -> None:
    store, case_id = store_case
    da = store.data_access_overview(case_id)
    assert da["totals"]["events"] > 0
    assert da["totals"]["bytes_out"] > 0  # the DB-dump exfil reads
    assert da["totals"]["deletes"] > 0  # cover-up deletes
    ops = {o["op"] for o in da["operations"]}
    assert {"read", "delete"} <= ops
    assert any("customer-db.sql.gz" in o["resource_id"] for o in da["top_objects"])


def test_data_access_event_query(store_case) -> None:
    store, case_id = store_case
    res = store.query_events(case_id, EventQuery(data_access=True, limit=50))
    assert res["total"] > 0
    sources = {e["ventra_source"] for e in res["events"]}
    assert "s3_access" in sources
    assert all(e.get("resource_id") for e in res["events"])
    facets = store.facets(case_id, EventQuery(data_access=True))
    assert facets["principal"]
    assert facets["event_outcome"]


# -- inventory ---------------------------------------------------------------------------

def test_inventory_summary(store_case) -> None:
    store, case_id = store_case
    inv = store.inventory_summary(case_id)
    assert inv["total_resources"] > 0
    assert "iam" in inv["sources"]
    assert inv["categories"], "rolled-up resource categories present"


def test_cloudtrail_collection(store_case) -> None:
    store, case_id = store_case
    ctc = store.cloudtrail_collection(case_id)
    assert "trails" in ctc
    assert "events" in ctc and "s3" in ctc["events"]
