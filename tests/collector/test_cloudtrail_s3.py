"""Unit tests for CloudTrail S3 log helpers."""

from __future__ import annotations

from collector.aws.control_plane.cloudtrail_s3 import (
    data_events_configured,
    insight_events_configured,
    lookup_event_category,
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
