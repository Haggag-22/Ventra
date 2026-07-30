"""Lookup-only CloudTrail collection must never touch S3."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from collector.engine.api.aws.control_plane.cloudtrail import CloudTrailCollector
from collector.lib.models import CollectionContext, TimeWindow

START = datetime(2026, 6, 11, 0, 0, 0, tzinfo=UTC)
END = datetime(2026, 6, 11, 23, 59, 59, tzinfo=UTC)


class _Cf:
    def __init__(self, *, lookup: list[dict[str, Any]] | None = None) -> None:
        self._lookup = lookup or [{"EventId": "lookup-mgmt"}]
        self.s3_calls = 0

    def paginate(self, service, region, operation, result_key, **kwargs):  # noqa: ANN001
        if service == "s3":
            self.s3_calls += 1
            return iter(())
        if service == "cloudtrail" and operation == "lookup_events":
            yield from self._lookup
        return iter(())

    def call(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        if args[:3] == ("cloudtrail", "us-east-1", "describe_trails"):
            return {
                "trailList": [
                    {
                        "Name": "main",
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main",
                        "S3BucketName": "trail-bucket",
                        "HomeRegion": "us-east-1",
                        "LogFileValidationEnabled": True,
                    }
                ]
            }
        if args[2] == "get_trail_status":
            return {"IsLogging": True}
        if args[2] == "get_event_selectors":
            return {"EventSelectors": [{"IncludeManagementEvents": True}]}
        if args[2] == "get_insight_selectors":
            return {"InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]}
        return {}

    def client(self, service: str, region: str) -> _Cf:
        return self


@pytest.fixture
def lookup_collector(tmp_path: Path) -> CloudTrailCollector:
    ctx = CollectionContext(
        cloud="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        time_window=TimeWindow(since=START, until=END),
        staging=tmp_path / "staging",
        case_id="CASE-TEST",
        artifact_parameters={"cloudtrail": {"collection_source": "lookup_events"}},
    )
    collector = CloudTrailCollector(ctx)
    collector.ctx.client_factory = _Cf()
    return collector


def test_lookup_mode_collect_skips_s3_and_validation(lookup_collector: CloudTrailCollector) -> None:
    cf: _Cf = lookup_collector.ctx.client_factory  # type: ignore[assignment]

    with patch.object(
        lookup_collector,
        "_validate_trail_logs",
        side_effect=AssertionError("validate_trail_logs must not run in lookup mode"),
    ), patch.object(
        lookup_collector,
        "_collect_s3_category",
        side_effect=AssertionError("_collect_s3_category must not run in lookup mode"),
    ):
        result = lookup_collector.collect()

    meta = json.loads(
        (lookup_collector.ctx.source_dir("cloudtrail") / "_meta.json").read_text(encoding="utf-8")
    )

    assert cf.s3_calls == 0
    assert result.record_count == 1
    assert meta.get("management_source") == "lookup_events"
    assert meta.get("data_events") == 0
    assert meta.get("network_activity_events") == 0
    assert meta.get("collection_source") == "lookup_events"
    assert meta["log_validation"].get("skipped") == "collection_source=lookup_events"
