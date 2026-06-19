"""Unit tests for CloudTrail S3 log helpers."""

from __future__ import annotations

import gzip
import io
import json
from datetime import UTC, datetime
from typing import Any

from collector.engine.api.aws.control_plane.cloudtrail_s3 import (
    MANAGEMENT_CATEGORIES,
    collect_s3_trail_records,
    data_events_configured,
    insight_events_configured,
    lookup_event_category,
    management_events_configured,
    merge_dedupe,
    network_activity_configured,
    trail_is_logging_to_s3,
    trail_s3_prefix,
)


def test_trail_s3_prefix_defaults_to_awslogs() -> None:
    assert trail_s3_prefix({"S3BucketName": "my-trail-bucket"}) == "AWSLogs/"


def test_trail_s3_prefix_honours_custom_prefix() -> None:
    assert trail_s3_prefix({"S3BucketName": "b", "S3KeyPrefix": "org/logs"}) == "org/logs/"


def test_data_events_configured_legacy_selectors() -> None:
    trail = {
        "EventSelectors": {
            "EventSelectors": [
                {
                    "IncludeManagementEvents": False,
                    "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}],
                }
            ]
        }
    }
    assert data_events_configured(trail) is True


def test_data_events_configured_advanced_selectors() -> None:
    trail = {
        "EventSelectors": {
            "AdvancedEventSelectors": [
                {
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                    ]
                }
            ]
        }
    }
    assert data_events_configured(trail) is True


def test_network_activity_configured() -> None:
    trail = {
        "EventSelectors": {
            "AdvancedEventSelectors": [
                {
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["NetworkActivity"]},
                    ]
                }
            ]
        }
    }
    assert network_activity_configured(trail) is True


def test_trail_is_logging_to_s3() -> None:
    assert trail_is_logging_to_s3({"S3BucketName": "b", "Status": {"IsLogging": True}})
    assert not trail_is_logging_to_s3({"S3BucketName": "b", "Status": {"IsLogging": False}})


def test_insight_events_configured() -> None:
    trail = {
        "InsightSelectors": {
            "InsightSelectors": [{"InsightType": "ApiCallRateInsight"}],
        }
    }
    assert insight_events_configured(trail) is True
    assert insight_events_configured({"InsightSelectors": None}) is False


def test_lookup_event_category_splits_insight() -> None:
    import json

    mgmt = {"CloudTrailEvent": json.dumps({"eventCategory": "Management", "eventID": "1"})}
    ins = {"CloudTrailEvent": json.dumps({"eventCategory": "Insight", "eventID": "2"})}
    assert lookup_event_category(mgmt) == "Management"
    assert lookup_event_category(ins) == "Insight"


def test_merge_dedupe_by_event_id() -> None:
    a = [{"eventID": "same-id"}]
    b = [{"CloudTrailEvent": '{"eventID":"same-id"}'}]
    c = [{"eventID": "other-id"}]
    merged = merge_dedupe(a, b, c)
    assert len(merged) == 2


def test_management_events_configured_default_is_on() -> None:
    # A default trail with no fetched selectors logs management events.
    assert management_events_configured({}) is True


def test_management_events_configured_classic_include_flag() -> None:
    on = {"EventSelectors": {"EventSelectors": [{"IncludeManagementEvents": True}]}}
    off = {
        "EventSelectors": {
            "EventSelectors": [{"IncludeManagementEvents": False, "DataResources": [{}]}]
        }
    }
    assert management_events_configured(on) is True
    assert management_events_configured(off) is False


def test_management_events_configured_advanced_selectors() -> None:
    mgmt = {
        "EventSelectors": {
            "AdvancedEventSelectors": [
                {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}
            ]
        }
    }
    data_only = {
        "EventSelectors": {
            "AdvancedEventSelectors": [
                {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}]}
            ]
        }
    }
    assert management_events_configured(mgmt) is True
    assert management_events_configured(data_only) is False


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3:
    def __init__(self, objects: dict[str, bytes]) -> None:
        self._objects = objects

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        return {"Body": _FakeBody(self._objects[Key])}


class _FakeCf:
    """Minimal client-factory stub for the S3 log reader."""

    def __init__(self, listing: list[dict[str, str]], objects: dict[str, bytes]) -> None:
        self._listing = listing
        self._s3 = _FakeS3(objects)

    def client(self, service: str, region: str) -> _FakeS3:
        return self._s3

    def paginate(self, service, region, operation, result_key, **kwargs):  # noqa: ANN001
        prefix = kwargs.get("Prefix", "")
        for obj in self._listing:
            if obj["Key"].startswith(prefix):
                yield obj

    def call(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}


def _gz(payload: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(json.dumps(payload).encode("utf-8"))
    return buf.getvalue()


def test_collect_management_from_shared_folder_filters_out_data() -> None:
    """Management collection reads the shared CloudTrail/ folder and drops data events."""
    key = "AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/11/log.json.gz"
    payload = {
        "Records": [
            {
                "eventCategory": "Management",
                "eventID": "m1",
                "eventTime": "2026-06-11T12:00:00Z",
                "eventName": "ConsoleLogin",
            },
            {
                "eventCategory": "Data",
                "eventID": "d1",
                "eventTime": "2026-06-11T12:01:00Z",
                "eventName": "GetObject",
            },
        ]
    }
    cf = _FakeCf([{"Key": key}], {key: _gz(payload)})
    trail = {
        "S3BucketName": "trail-bucket",
        "S3KeyPrefix": "",
        "HomeRegion": "us-east-1",
        "IsMultiRegionTrail": False,
        "Status": {"IsLogging": True},
    }
    start = datetime(2026, 6, 11, 0, 0, 0, tzinfo=UTC)
    end = datetime(2026, 6, 11, 23, 59, 59, tzinfo=UTC)
    gaps: list[tuple[str, Any, str]] = []

    records, stats = collect_s3_trail_records(
        cf, trail, "123456789012", ["us-east-1"], start, end, MANAGEMENT_CATEGORIES, gaps
    )

    assert [r["eventID"] for r in records] == ["m1"]
    assert records[0]["_ventra_collect_source"] == "s3_logs"
    assert records[0]["_ventra_s3_bucket"] == "trail-bucket"
    assert stats["records"] == 1
