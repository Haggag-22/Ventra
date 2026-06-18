"""M365 CRITICAL collectors + normalizers — UAL (incl. MailItemsAccessed) and OAuth consent."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from collector.azure.client_factory import AzureServiceNotEnabled
from collector.azure.identity.oauth_consent import OAuthConsentCollector
from collector.azure.m365.unified_audit import UnifiedAuditCollector
from collector.azure.m365.unified_audit_search import UnifiedAuditSearchCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow, UalCollectOptions

from ventra_ingester.normalizer.base import NormalizeContext
from ventra_ingester.normalizer.sources.m365 import (
    normalize_oauth_consent,
    normalize_unified_audit,
)

CTX = NormalizeContext(case_id="CASE-AZ", account_id="tenant-abc")


class _FakeCf:
    def __init__(self, *, content=None, content_error=None, graph=None, search=None) -> None:
        self._content = content or {}
        self._content_error = content_error
        self._graph = graph or {}
        self._search = search or []

    def management_content(self, content_type, start, end, *, max_records=200_000):  # noqa: ANN001
        if self._content_error is not None:
            raise self._content_error
        yield from self._content.get(content_type, [])

    def search_unified_audit_log(self, start, end, *, users=None, operations=None, record_types=None,  # noqa: ANN001
                                 ip_addresses=None, max_records=200_000, audit_data_only=False):
        yield from self._search

    def graph_paginate(self, path, *, params=None, max_records=200_000):  # noqa: ANN001
        yield from self._graph.get(path, [])


def _ctx(tmp_path: Path, cf: _FakeCf, window: TimeWindow | None = None,
         ual: UalCollectOptions | None = None) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return CollectionContext(
        cloud="azure", account_id="tenant-abc", regions=[],
        time_window=window or TimeWindow(), staging=staging, case_id="CASE-AZ",
        tenant_id="tenant-abc", subscription_ids=[], client_factory=cf,
        ual=ual or UalCollectOptions(),
    )


# -- collectors --------------------------------------------------------------------------

def test_unified_audit_collects(tmp_path: Path) -> None:
    cf = _FakeCf(content={
        "Audit.Exchange": [
            {"CreationTime": "2026-06-08T01:00:00Z", "Operation": "MailItemsAccessed",
             "Workload": "Exchange", "UserId": "victim@corp.com", "ClientIP": "203.0.113.7",
             "ResultStatus": "Succeeded", "ObjectId": "msg-1"},
        ],
    })
    # Past window so the ingestion-lag note does not fire.
    win = TimeWindow(since=datetime(2026, 6, 1, tzinfo=UTC), until=datetime(2026, 6, 2, tzinfo=UTC))
    result = UnifiedAuditCollector(_ctx(tmp_path, cf, win)).collect()
    # Some content types have no data (feed not in fake) but at least one collected.
    assert result.record_count == 1
    assert result.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)


def test_unified_audit_feed_not_enabled_is_a_gap(tmp_path: Path) -> None:
    cf = _FakeCf(content_error=AzureServiceNotEnabled("manage:Audit.Exchange", "feed not enabled"))
    win = TimeWindow(since=datetime(2026, 6, 1, tzinfo=UTC), until=datetime(2026, 6, 2, tzinfo=UTC))
    result = UnifiedAuditCollector(_ctx(tmp_path, cf, win)).collect()
    assert result.record_count == 0
    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)


def test_unified_audit_flags_ingestion_lag(tmp_path: Path) -> None:
    cf = _FakeCf(content={})  # no data, window ends "now"
    result = UnifiedAuditCollector(_ctx(tmp_path, cf, TimeWindow())).collect()
    assert "ingestion-lag" in result.notes.lower() or "lag" in result.notes.lower()


def test_unified_audit_filters_operations(tmp_path: Path) -> None:
    cf = _FakeCf(content={
        "Audit.Exchange": [
            {"CreationTime": "2026-06-08T01:00:00Z", "Operation": "MailItemsAccessed",
             "Workload": "Exchange", "UserId": "victim@corp.com"},
            {"CreationTime": "2026-06-08T02:00:00Z", "Operation": "Send",
             "Workload": "Exchange", "UserId": "victim@corp.com"},
        ],
    })
    win = TimeWindow(since=datetime(2026, 6, 1, tzinfo=UTC), until=datetime(2026, 6, 2, tzinfo=UTC))
    ual = UalCollectOptions(operations=["MailItemsAccessed"])
    result = UnifiedAuditCollector(_ctx(tmp_path, cf, win, ual)).collect()
    assert result.record_count == 1


def test_unified_audit_search_collects(tmp_path: Path) -> None:
    cf = _FakeCf(search=[
        {"CreationTime": "2026-06-08T01:00:00Z", "Operation": "MailItemsAccessed",
         "Workload": "Exchange", "UserId": "victim@corp.com", "_ventra_ual_acquisition": "search"},
    ])
    win = TimeWindow(since=datetime(2026, 6, 1, tzinfo=UTC), until=datetime(2026, 6, 2, tzinfo=UTC))
    result = UnifiedAuditSearchCollector(_ctx(tmp_path, cf, win)).collect()
    assert result.record_count == 1
    assert result.status == SourceStatus.COLLECTED


def test_oauth_consent_collects(tmp_path: Path) -> None:
    cf = _FakeCf(graph={"oauth2PermissionGrants": [
        {"clientId": "app-666", "principalId": "u-1", "consentType": "Principal",
         "scope": "Mail.Read Mail.Send", "resourceId": "graph"},
    ]})
    result = OAuthConsentCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1


# -- normalizers -------------------------------------------------------------------------

def test_normalize_mailitemsaccessed_is_data_access() -> None:
    rec = {"CreationTime": "2026-06-08T01:00:00Z", "Operation": "MailItemsAccessed",
           "Workload": "Exchange", "UserId": "victim@corp.com", "ClientIP": "203.0.113.7",
           "ResultStatus": "Succeeded", "ObjectId": "msg-1"}
    ev = next(iter(normalize_unified_audit([rec], CTX)))
    assert "data" in ev.event_category
    assert ev.source_ip == "203.0.113.7"
    assert ev.user_name == "victim@corp.com"
    assert ev.ventra_source == "unified_audit"


def test_normalize_consent_op_is_persistence() -> None:
    rec = {"CreationTime": "2026-06-08T01:05:00Z", "Operation": "Consent to application.",
           "Workload": "AzureActiveDirectory", "UserId": "admin@corp.com", "ResultStatus": "Success"}
    ev = next(iter(normalize_unified_audit([rec], CTX)))
    assert "persistence" in ev.event_category
    assert ev.event_severity == "high"


def test_normalize_oauth_grant_is_finding() -> None:
    rec = {"clientId": "app-666", "principalId": "u-1", "consentType": "Principal",
           "scope": "Mail.Read Mail.Send", "resourceId": "graph"}
    ev = next(iter(normalize_oauth_consent([rec], CTX)))
    assert ev.event_kind == "finding"
    assert "persistence" in ev.event_category
    assert "Mail.Read" in ev.message
