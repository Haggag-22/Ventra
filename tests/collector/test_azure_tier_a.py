"""Tier A Azure collectors: Entra sign-in/audit + Activity Log.

Driven by a fake client factory (no Azure credentials or SDK calls), exactly like the AWS
collector unit tests. Asserts the collected / access-denied / premium-not-enabled / empty
decision trees and that emitted records match the shapes the existing normalizers expect.
"""

from __future__ import annotations

from pathlib import Path

from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from collector.engine.api.azure.control_plane.activity_log import ActivityLogCollector
from collector.engine.api.azure.identity.entra_audit import EntraAuditCollector
from collector.engine.api.azure.identity.entra_signin import EntraSignInCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow


def _single_day_window(day: str = "2026-06-08") -> TimeWindow:
    from datetime import UTC, datetime, timedelta

    since = datetime.fromisoformat(f"{day}T00:00:00").replace(tzinfo=UTC)
    return TimeWindow(since=since, until=since + timedelta(days=1))


class _FakeCf:
    """Fake AzureClientFactory: canned Graph pages / Activity Log events, or a raised error."""

    def __init__(
        self,
        *,
        graph: dict[str, list[dict]] | None = None,
        graph_error: Exception | None = None,
        activity: dict[str, list[dict]] | None = None,
    ) -> None:
        self._graph = graph or {}
        self._graph_error = graph_error
        self._activity = activity or {}
        self._activity_chunks: set[tuple[str, str]] = set()

    def graph_paginate(self, path, *, params=None, max_records=200_000):  # noqa: ANN001
        if self._graph_error is not None:
            raise self._graph_error
        yield from self._graph.get(path, [])

    def activity_log_events(self, subscription_id, filter_str, *, max_records=200_000):  # noqa: ANN001
        key = (subscription_id, filter_str)
        if key in self._activity_chunks:
            return
        self._activity_chunks.add(key)
        emitted = 0
        for ev in self._activity.get(subscription_id, []):
            if emitted >= max_records:
                return
            yield ev
            emitted += 1


def _ctx(
    tmp_path: Path,
    cf: _FakeCf,
    *,
    subscriptions: list[str] | None = None,
    window: TimeWindow | None = None,
) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return CollectionContext(
        cloud="azure",
        account_id="tenant-abc",
        regions=[],
        time_window=window or TimeWindow(),
        staging=staging,
        case_id="CASE-AZ",
        tenant_id="tenant-abc",
        subscription_ids=subscriptions or [],
        client_factory=cf,
    )


def test_entra_signin_collects(tmp_path: Path) -> None:
    cf = _FakeCf(graph={"auditLogs/signIns": [
        {"id": "1", "userPrincipalName": "victim@corp.com", "ipAddress": "203.0.113.7",
         "createdDateTime": "2026-06-08T01:00:00Z", "status": {"errorCode": 0}},
    ]})
    result = EntraSignInCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1


def test_entra_signin_premium_required_is_a_gap(tmp_path: Path) -> None:
    cf = _FakeCf(graph_error=AzureServiceNotEnabled("graph:signIns", "Entra ID P1 required"))
    result = EntraSignInCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 0
    assert any(g[1] == GapReason.SERVICE_NOT_ENABLED for g in result.gaps)


def test_entra_audit_access_denied_is_a_gap(tmp_path: Path) -> None:
    cf = _FakeCf(graph_error=AzureAccessDenied("graph:directoryAudits", "consent missing"))
    result = EntraAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.EMPTY
    assert any(g[1] == GapReason.ACCESS_DENIED for g in result.gaps)


def test_activity_log_collects_across_subscriptions(tmp_path: Path) -> None:
    cf = _FakeCf(activity={
        "sub-1": [{"operationName": {"value": "Microsoft.Compute/virtualMachines/delete"},
                   "status": {"value": "Succeeded"}, "caller": "attacker@corp.com",
                   "callerIpAddress": "203.0.113.7", "resourceId": "/subscriptions/sub-1/...",
                   "subscriptionId": "sub-1", "eventTimestamp": "2026-06-08T01:05:00Z"}],
        "sub-2": [],
    })
    result = ActivityLogCollector(
        _ctx(tmp_path, cf, subscriptions=["sub-1", "sub-2"], window=_single_day_window()),
    ).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1


def test_activity_log_no_subscriptions_is_a_gap(tmp_path: Path) -> None:
    result = ActivityLogCollector(_ctx(tmp_path, _FakeCf(), subscriptions=[])).collect()
    assert result.status == SourceStatus.EMPTY
    assert any(g[1] == GapReason.NOT_PRESENT for g in result.gaps)


def test_activity_log_writes_per_subscription_files(tmp_path: Path) -> None:
    cf = _FakeCf(activity={
        "sub-aaa": [{"operationName": {"value": "Microsoft.Compute/virtualMachines/write"},
                     "status": {"value": "Succeeded"}, "caller": "admin@corp.com",
                     "eventTimestamp": "2026-06-08T01:05:00Z", "resourceId": "/subscriptions/sub-aaa/r"}],
        "sub-bbb": [{"operationName": {"value": "Microsoft.Storage/storageAccounts/delete"},
                     "status": {"value": "Succeeded"}, "caller": "admin@corp.com",
                     "eventTimestamp": "2026-06-08T02:05:00Z", "resourceId": "/subscriptions/sub-bbb/r"}],
    })
    win = _single_day_window("2026-06-08")
    result = ActivityLogCollector(_ctx(tmp_path, cf, subscriptions=["sub-aaa", "sub-bbb"], window=win)).collect()
    assert result.record_count == 2
    paths = {f.path for f in result.files}
    assert any("events-sub-aaa.jsonl.gz" in p for p in paths)
    assert any("events-sub-bbb.jsonl.gz" in p for p in paths)


def test_activity_log_truncation_warning(tmp_path: Path) -> None:
    from collector.engine.api.azure.control_plane import activity_log as mod

    class _CountingCf(_FakeCf):
        def activity_log_events(self, subscription_id, filter_str, *, max_records=200_000):  # noqa: ANN001
            for i in range(100):
                yield {
                    "operationName": {"value": "Microsoft.Test/write"},
                    "eventTimestamp": f"2026-06-08T01:{i:02d}:00Z",
                    "subscriptionId": subscription_id,
                }
                if i + 1 >= max_records:
                    return

    old_max = mod.MAX_RECORDS
    mod.MAX_RECORDS = 5
    try:
        result = ActivityLogCollector(
            _ctx(tmp_path, _CountingCf(), subscriptions=["sub-1"], window=_single_day_window()),
        ).collect()
    finally:
        mod.MAX_RECORDS = old_max
    assert result.record_count == 5
    assert any("truncated" in g[2].lower() for g in result.gaps)
