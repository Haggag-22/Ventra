"""GCP audit/LB source reclassification and the load-balancer-family normalizer."""

from __future__ import annotations

from ventra_ingester.normalizer.base import NormalizeContext, has_normalizer, normalize_source
from ventra_ingester.normalizer.sources.gcp_audit import _audit_event, _lb_event

CTX = NormalizeContext(case_id="CASE-TEST", account_id="my-project")


def _audit_rec(service: str, method: str = "some.Method") -> dict:
    return {
        "timestamp": "2026-06-15T10:00:00Z",
        "severity": "INFO",
        "protoPayload": {"serviceName": service, "methodName": method},
        "resource": {"type": "audited_resource", "labels": {}},
    }


def test_shared_table_row_reclassified_by_service() -> None:
    ev = _audit_event(_audit_rec("storage.googleapis.com"), CTX, "cloud_audit_data")
    assert ev.ventra_source == "storage_access"


def test_shared_table_row_unmapped_service_stays_broad() -> None:
    ev = _audit_event(_audit_rec("iam.googleapis.com"), CTX, "cloud_audit_data")
    assert ev.ventra_source == "cloud_audit_data"


def test_standalone_subset_collection_untouched() -> None:
    # A subset collected on its own (no dedup) is already correctly tagged — the reclassify
    # guard only fires for source == "cloud_audit_data", so this must pass through unchanged.
    ev = _audit_event(_audit_rec("storage.googleapis.com"), CTX, "storage_access")
    assert ev.ventra_source == "storage_access"


def test_admin_and_system_streams_never_reclassified() -> None:
    ev = _audit_event(_audit_rec("compute.googleapis.com"), CTX, "cloud_audit_admin")
    assert ev.ventra_source == "cloud_audit_admin"


def _lb_rec(*, cache_decision=None, armor_policy=None, status="200") -> dict:
    rec: dict = {
        "timestamp": "2026-06-15T10:00:00Z",
        "httpRequest": {
            "requestMethod": "GET",
            "requestUrl": "https://shop.example.com/checkout",
            "status": status,
            "remoteIp": "203.0.113.66",
        },
        "resource": {"type": "http_load_balancer", "labels": {"forwarding_rule_name": "web-lb"}},
        "jsonPayload": {},
    }
    if cache_decision is not None:
        rec["jsonPayload"]["cacheDecision"] = cache_decision
    if armor_policy is not None:
        rec["jsonPayload"]["enforcedSecurityPolicy"] = {"name": armor_policy}
    return rec


def test_lb_row_without_cdn_or_armor_stays_load_balancer() -> None:
    ev = _lb_event(_lb_rec(), CTX, "load_balancer")
    assert ev.ventra_source == "load_balancer"
    assert ev.message == "GET https://shop.example.com/checkout → 200 (web-lb)"
    assert ev.event_outcome == "success"


def test_lb_row_with_cache_decision_reclassified_to_cdn() -> None:
    ev = _lb_event(_lb_rec(cache_decision=["HIT"]), CTX, "load_balancer")
    assert ev.ventra_source == "cloud_cdn"


def test_lb_row_with_armor_policy_reclassified_to_armor() -> None:
    ev = _lb_event(_lb_rec(armor_policy="default-policy"), CTX, "load_balancer")
    assert ev.ventra_source == "cloud_armor"


def test_lb_row_failure_status_maps_to_failure_outcome() -> None:
    ev = _lb_event(_lb_rec(status="403"), CTX, "load_balancer")
    assert ev.event_outcome == "failure"
    assert "→ 403" in ev.message


def test_standalone_cdn_and_armor_collection_no_longer_silently_dropped() -> None:
    # Before this fix, cloud_cdn/cloud_armor had no registered normalizer at all — a
    # standalone collection of either was silently dropped at ingest (has_normalizer was
    # False, normalize_source returned nothing). Confirm both are now registered and
    # produce events even without going through the load_balancer dedup path.
    for source in ("cloud_cdn", "cloud_armor"):
        assert has_normalizer(source), f"{source} has no registered normalizer"
        out = list(normalize_source(source, [_lb_rec()], CTX))
        assert len(out) == 1
        assert out[0].ventra_source == source


def test_load_balancer_still_registered() -> None:
    assert has_normalizer("load_balancer")
    out = list(normalize_source("load_balancer", [_lb_rec(cache_decision=["HIT"])], CTX))
    assert len(out) == 1
    assert out[0].ventra_source == "cloud_cdn"
