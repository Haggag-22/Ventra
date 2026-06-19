"""Log Analytics collector unit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from collector.engine.api.azure.control_plane.log_analytics import LogAnalyticsCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow

WORKSPACE = (
    "/subscriptions/sub-1/resourceGroups/prod-rg/providers/"
    "Microsoft.OperationalInsights/workspaces/la-prod"
)
APP_GW = (
    "/subscriptions/sub-1/resourceGroups/prod-rg/providers/"
    "Microsoft.Network/applicationGateways/appgw-prod"
)


class _FakeCf:
    def __init__(self) -> None:
        self.queries: list[tuple[str, str]] = []

    def resources_of_type(self, subscription_id, resource_types):  # noqa: ANN001
        if "applicationGateways" in resource_types[0]:
            return [{"id": APP_GW, "name": "appgw-prod", "type": resource_types[0], "location": "eastus"}]
        return []

    def diagnostic_settings(self, resource_id):  # noqa: ANN001
        if resource_id == APP_GW:
            return [{
                "workspace_id": WORKSPACE,
                "storage_account_id": "",
                "event_hub": "",
                "categories": ["ApplicationGatewayAccessLog", "ApplicationGatewayFirewallLog"],
            }]
        return []

    def log_analytics_query(self, workspace_id, query, *, timespan=None, max_records=200_000):  # noqa: ANN001
        self.queries.append((workspace_id, query))
        return [
            {
                "TimeGenerated": "2026-06-08T01:05:00Z",
                "ResourceId": APP_GW,
                "Category": "ApplicationGatewayAccessLog",
                "clientIP_s": "203.0.113.7",
                "httpMethod_s": "GET",
                "requestUri_s": "/api/export",
                "httpStatus_d": 200,
            },
            {
                "TimeGenerated": "2026-06-08T01:06:00Z",
                "ResourceId": APP_GW,
                "Category": "ApplicationGatewayFirewallLog",
                "clientIP_s": "203.0.113.7",
                "action_s": "BLOCK",
                "ruleId_s": "942100",
            },
        ]


def _ctx(tmp_path: Path, cf: _FakeCf) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    since = datetime(2026, 6, 8, tzinfo=UTC)
    return CollectionContext(
        cloud="azure",
        account_id="tenant-abc",
        regions=[],
        time_window=TimeWindow(since=since, until=since + timedelta(days=1)),
        staging=staging,
        case_id="CASE-AZ",
        tenant_id="tenant-abc",
        subscription_ids=["sub-1"],
        client_factory=cf,
    )


def test_log_analytics_collects_la_routed_diagnostics(tmp_path: Path) -> None:
    cf = _FakeCf()
    result = LogAnalyticsCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 2
    assert cf.queries and cf.queries[0][0] == WORKSPACE
    assert "ApplicationGatewayAccessLog" in cf.queries[0][1]


def test_log_analytics_no_workspace_is_a_gap(tmp_path: Path) -> None:
    class _NoLaCf(_FakeCf):
        def diagnostic_settings(self, resource_id):  # noqa: ANN001
            return [{"workspace_id": "", "storage_account_id": "sa1", "categories": ["ApplicationGatewayAccessLog"]}]

    result = LogAnalyticsCollector(_ctx(tmp_path, _NoLaCf())).collect()
    assert result.record_count == 0
    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)
