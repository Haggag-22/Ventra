"""Unit tests for the access-log collectors and the logging-posture collector."""

from __future__ import annotations

import gzip
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from collector.aws.control_plane.log_posture import LogPostureCollector
from collector.aws.network.elb_alb import ElbAlbCollector
from collector.aws.workloads.eks_audit import EksAuditCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow

START = datetime(2026, 6, 11, 0, 0, 0, tzinfo=UTC)
END = datetime(2026, 6, 11, 23, 59, 59, tzinfo=UTC)

ALB_LINE = (
    'https 2026-06-11T12:00:00.000000Z app/web-alb/abc 203.0.113.66:34567 10.0.1.5:80 '
    '0.0 0.001 0.0 200 200 34 366 "GET https://x.example.com:443/ HTTP/1.1" "UA" c p arn '
    '"t" "d" "-" 0 2026-06-11T12:00:00.000000Z "forward" "-" "-" "10.0.1.5:80" "200" "-" "-"'
)


def _gz_lines(*lines: str) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(("\n".join(lines) + "\n").encode())
    return buf.getvalue()


class _Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _S3:
    def __init__(self, objects: dict[str, bytes]) -> None:
        self._objects = objects

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        return {"Body": _Body(self._objects[Key])}


class _Cf:
    """Dispatch-table client-factory stub: (service, operation) -> pages / response."""

    def __init__(
        self,
        pages: dict[tuple[str, str], list] | None = None,
        calls: dict[tuple[str, str], Any] | None = None,
        s3_objects: dict[str, bytes] | None = None,
    ) -> None:
        self.pages = pages or {}
        self.calls = calls or {}
        self.s3_objects = s3_objects or {}

    def paginate(self, service, region, operation, result_key, **kwargs):  # noqa: ANN001
        if (service, operation) == ("s3", "list_objects_v2"):
            prefix = kwargs.get("Prefix", "")
            for key in self.s3_objects:
                if key.startswith(prefix):
                    yield {"Key": key}
            return
        yield from self.pages.get((service, operation), [])

    def call(self, service, region, operation, **kwargs):  # noqa: ANN001
        value = self.calls.get((service, operation), {})
        return value(**kwargs) if callable(value) else value

    def client(self, service: str, region: str) -> _S3:
        return _S3(self.s3_objects)


def _ctx(tmp_path: Path, cf: _Cf) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return CollectionContext(
        cloud="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        time_window=TimeWindow(since=START, until=END),
        staging=staging,
        case_id="CASE-TEST",
        client_factory=cf,
    )


def test_elb_alb_collects_logs_and_flags_unlogged_lbs(tmp_path: Path) -> None:
    key = "AWSLogs/123456789012/elasticloadbalancing/us-east-1/2026/06/11/x.log.gz"
    cf = _Cf(
        pages={
            ("elbv2", "describe_load_balancers"): [
                {
                    "LoadBalancerArn": "arn:lb/web-alb",
                    "LoadBalancerName": "web-alb",
                    "Type": "application",
                    "DNSName": "web.example.com",
                },
                {
                    "LoadBalancerArn": "arn:lb/dark-alb",
                    "LoadBalancerName": "dark-alb",
                    "Type": "application",
                    "DNSName": "dark.example.com",
                },
            ],
            ("elb", "describe_load_balancers"): [],
        },
        calls={
            ("elbv2", "describe_load_balancer_attributes"): lambda LoadBalancerArn: {
                "Attributes": [
                    {
                        "Key": "access_logs.s3.enabled",
                        "Value": "true" if "web-alb" in LoadBalancerArn else "false",
                    },
                    {"Key": "access_logs.s3.bucket", "Value": "lb-logs"},
                    {"Key": "access_logs.s3.prefix", "Value": ""},
                ]
            },
            ("s3", "get_bucket_location"): {"LocationConstraint": None},
        },
        s3_objects={key: _gz_lines(ALB_LINE)},
    )

    result = ElbAlbCollector(_ctx(tmp_path, cf)).collect()

    assert result.record_count == 1
    assert result.status == SourceStatus.PARTIAL  # one LB unlogged -> gap
    gap_reasons = {g[1] for g in result.gaps}
    assert GapReason.LOGGING_NOT_CONFIGURED in gap_reasons
    assert any("dark-alb" in g[2] for g in result.gaps)


def test_eks_audit_disabled_cluster_is_a_gap(tmp_path: Path) -> None:
    cf = _Cf(
        pages={("eks", "list_clusters"): ["prod"]},
        calls={
            ("eks", "describe_cluster"): {
                "cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/prod",
                    "version": "1.29",
                    "logging": {"clusterLogging": [{"types": ["api"], "enabled": True}]},
                }
            }
        },
    )
    result = EksAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 0
    assert any(
        g[1] == GapReason.LOGGING_NOT_CONFIGURED and "prod" in g[2] for g in result.gaps
    )


def test_eks_audit_pulls_cloudwatch_audit_events(tmp_path: Path) -> None:
    audit_event = {
        "kind": "Event",
        "stage": "ResponseComplete",
        "verb": "get",
        "user": {"username": "admin"},
        "objectRef": {"resource": "secrets", "name": "db-creds"},
        "stageTimestamp": "2026-06-11T10:00:00Z",
    }
    cf = _Cf(
        pages={
            ("eks", "list_clusters"): ["prod"],
            ("logs", "filter_log_events"): [{"message": json.dumps(audit_event)}],
        },
        calls={
            ("eks", "describe_cluster"): {
                "cluster": {
                    "arn": "arn:cluster/prod",
                    "version": "1.29",
                    "logging": {"clusterLogging": [{"types": ["audit"], "enabled": True}]},
                }
            }
        },
    )
    result = EksAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1


def test_log_posture_emits_per_source_gaps(tmp_path: Path) -> None:
    cf = _Cf(
        pages={
            ("apigateway", "get_rest_apis"): [{"id": "api1"}],
            ("rds", "describe_db_instances"): [
                {"DBInstanceIdentifier": "db1", "EnabledCloudwatchLogsExports": []}
            ],
            ("logs", "describe_log_groups"): [],
            ("dynamodb", "list_tables"): [],
            ("network-firewall", "list_firewalls"): [],
        },
        calls={
            ("apigateway", "get_stages"): {
                "item": [
                    {
                        "stageName": "prod",
                        "accessLogSettings": {
                            "destinationArn": "arn:aws:logs:us-east-1:1:log-group:apigw"
                        },
                    }
                ]
            },
            ("opensearch", "list_domain_names"): {"DomainNames": []},
        },
    )
    result = LogPostureCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED

    by_name = {g[0]: g for g in result.gaps}
    # API GW: logging enabled but Ventra can't pull it yet -> out_of_scope with destination.
    assert by_name["apigateway"][1] == GapReason.OUT_OF_SCOPE
    assert "log-group:apigw" in by_name["apigateway"][2]
    # RDS: instances exist, no exports -> logging_not_configured (a finding).
    assert by_name["rds"][1] == GapReason.LOGGING_NOT_CONFIGURED
    # Empty services -> not_present.
    assert by_name["lambda_logs"][1] == GapReason.NOT_PRESENT
    assert by_name["dynamodb_streams"][1] == GapReason.NOT_PRESENT
    assert by_name["network_firewall"][1] == GapReason.NOT_PRESENT
    assert by_name["opensearch"][1] == GapReason.NOT_PRESENT
