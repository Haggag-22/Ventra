"""Tests for collector artifact parameter helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from collector.lib.params import (
    effective_window,
    param_bool,
    param_strings,
)
from collector.lib.scoping import (
    cloudtrail_event_matches,
    filter_cloudtrail_trails,
    filter_eks_clusters,
    filter_guardduty_findings,
    filter_iam_bindings,
    filter_scc_findings,
    filter_vpc_flow_logs,
    gcp_logging_filter_extension,
)
from collector.lib.models import CollectionContext, TimeWindow


def test_param_strings_from_list_and_scalar() -> None:
    assert param_strings({"vpc_ids": ["vpc-1", "vpc-2"]}, "vpc_ids") == ["vpc-1", "vpc-2"]
    assert param_strings({"vpc_ids": "vpc-a, vpc-b"}, "vpc_ids") == ["vpc-a", "vpc-b"]
    assert param_strings({}, "vpc_ids") == []


def test_param_bool() -> None:
    assert param_bool({"include_user_data": True}, "include_user_data") is True
    assert param_bool({"include_user_data": "false"}, "include_user_data") is False
    assert param_bool({}, "include_user_data") is False
    assert param_bool({}, "include_user_data", default=True) is True


def test_filter_cloudtrail_trails() -> None:
    trails = [
        {"TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/a", "Name": "a", "S3BucketName": "b1"},
        {"TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/b", "Name": "b", "S3BucketName": "b2"},
    ]
    filtered = filter_cloudtrail_trails(trails, {"trail_names": ["a"]})
    assert len(filtered) == 1
    assert filtered[0]["Name"] == "a"


def test_filter_vpc_flow_logs_by_vpc() -> None:
    logs = [
        {"FlowLogId": "fl-1", "ResourceId": "vpc-abc", "LogDestinationType": "s3"},
        {"FlowLogId": "fl-2", "ResourceId": "vpc-xyz", "LogDestinationType": "s3"},
    ]
    filtered = filter_vpc_flow_logs(logs, {"vpc_ids": ["vpc-abc"]})
    assert len(filtered) == 1
    assert filtered[0]["ResourceId"] == "vpc-abc"


def test_filter_eks_clusters() -> None:
    clusters = [
        {"name": "prod", "arn": "arn:aws:eks:us-east-1:1:cluster/prod"},
        {"name": "dev", "arn": "arn:aws:eks:us-east-1:1:cluster/dev"},
    ]
    filtered = filter_eks_clusters(clusters, {"cluster_names": ["prod"]})
    assert len(filtered) == 1
    assert filtered[0]["name"] == "prod"


def test_filter_eks_clusters_by_log_group() -> None:
    clusters = [{"name": "prod", "arn": "arn:cluster/prod"}, {"name": "dev", "arn": "arn:cluster/dev"}]
    filtered = filter_eks_clusters(clusters, {"log_group_names": ["/aws/eks/prod/cluster"]})
    assert len(filtered) == 1
    assert filtered[0]["name"] == "prod"


def test_cloudtrail_event_matches() -> None:
    rec = {"eventName": "ConsoleLogin", "userIdentity": {"userName": "alice", "arn": "arn:user/alice"}}
    assert cloudtrail_event_matches({"event_names": ["ConsoleLogin"]}, rec)
    assert cloudtrail_event_matches({"username": ["alice"]}, rec)
    assert not cloudtrail_event_matches({"event_names": ["AssumeRole"]}, rec)


def test_filter_guardduty_findings_severity() -> None:
    findings = [{"Id": "f1", "Severity": 8}, {"Id": "f2", "Severity": 3}]
    filtered = filter_guardduty_findings(findings, {"severity_min": 5})
    assert len(filtered) == 1
    assert filtered[0]["Id"] == "f1"


def test_filter_iam_bindings() -> None:
    bindings = [
        {"role": "roles/viewer", "members": ["user:alice@example.com"]},
        {"role": "roles/owner", "members": ["user:bob@example.com"]},
    ]
    filtered = filter_iam_bindings(bindings, {"roles": ["roles/viewer"]})
    assert len(filtered) == 1


def test_filter_scc_findings() -> None:
    findings = [
        {"severity": "HIGH", "state": "ACTIVE", "resourceName": "//cloudresourcemanager.googleapis.com/projects/p1"},
        {"severity": "LOW", "state": "INACTIVE", "resourceName": "//cloudresourcemanager.googleapis.com/projects/p2"},
    ]
    filtered = filter_scc_findings(findings, {"severity": ["HIGH"], "project_ids": ["p1"]})
    assert len(filtered) == 1


def test_gcp_logging_filter_extension_http_status() -> None:
    ext = gcp_logging_filter_extension({"http_status": "403", "search_text": "malware"})
    assert "httpRequest.status=403" in ext
    assert "textPayload" in ext


def test_gcp_logging_filter_extension_data_storage() -> None:
    ext = gcp_logging_filter_extension(
        {
            "dataset_ids": ["analytics"],
            "table_ids": ["events"],
            "instance_names": ["prod-mysql"],
            "secret_names": ["api-key"],
        }
    )
    assert 'resource.labels.dataset_id="analytics"' in ext
    assert 'resource.labels.table_id="events"' in ext
    assert 'resource.labels.database_id="prod-mysql"' in ext
    assert 'resource.labels.secret_id="api-key"' in ext


def test_effective_window_relative_since(tmp_path) -> None:
    end = datetime(2026, 6, 15, tzinfo=UTC)
    ctx = CollectionContext(
        cloud="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        staging=tmp_path,
        case_id="CASE-TEST",
        time_window=TimeWindow(since=None, until=end),
        artifact_parameters={"cloudtrail": {"since": "30d"}},
    )
    start, out_end = effective_window(ctx, "cloudtrail", default_days=90)
    assert out_end == end
    assert (end - start).days == 30
