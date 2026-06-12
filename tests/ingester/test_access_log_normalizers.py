"""Parser + normalizer tests for the access-log, DNS, EKS-audit, and Inspector2 sources."""

from __future__ import annotations

from ventra_ingester.normalizer.base import NormalizeContext
from ventra_ingester.normalizer.sources.access_logs import (
    normalize_cloudfront,
    normalize_elb_alb,
    normalize_s3_access,
    parse_cloudfront_line,
    parse_elb_line,
    parse_s3_access_line,
)
from ventra_ingester.normalizer.sources.dns_logs import normalize_route53_resolver
from ventra_ingester.normalizer.sources.eks_audit import normalize_eks_audit
from ventra_ingester.normalizer.sources.findings import normalize_inspector2

CTX = NormalizeContext(case_id="CASE-TEST", account_id="123456789012")

ALB_LINE = (
    'https 2026-06-08T01:10:05.123456Z app/web-alb/50dc6c495c0c9188 '
    '203.0.113.66:34567 10.0.1.5:80 0.000 0.001 0.000 403 403 34 366 '
    '"GET https://shop.example.com:443/admin/login HTTP/1.1" "Mozilla/5.0" '
    'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 '
    'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/abc '
    '"Root=1-abc" "shop.example.com" "-" 0 2026-06-08T01:10:05.120000Z '
    '"forward" "-" "-" "10.0.1.5:80" "403" "-" "-"'
)

CLB_LINE = (
    '2026-06-08T01:11:00.123456Z my-clb 203.0.113.66:34567 10.0.1.5:80 '
    '0.00005 0.0006 0.00003 200 200 0 57 "GET https://example.com:443/ HTTP/1.1" '
    '"curl/7.88" ECDHE-RSA-AES128 TLSv1.2'
)

CF_FIELDS = (
    "date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem "
    "sc-status cs(Referer) cs(User-Agent) cs-uri-query"
)
CF_LINE = (
    "2026-06-08\t01:12:00\tIAD89-C1\t492\t203.0.113.66\tGET\t"
    "d111abcdef8.cloudfront.net\t/wp-admin/setup.php\t404\t-\tMozilla/5.0\t-"
)

S3_LINE = (
    "79a59df900b949e55d96a1e698fbaced exfil-staging "
    "[08/Jun/2026:01:20:01 +0000] 203.0.113.66 "
    "arn:aws:iam::123456789012:user/dbadmin 3E57427F3EXAMPLE REST.GET.OBJECT "
    'customer-db.sql.gz "GET /exfil-staging/customer-db.sql.gz HTTP/1.1" 200 - '
    '1048576 1048576 45 12 "-" "aws-cli/2.15" - abc= SigV4 '
    "ECDHE-RSA-AES128-GCM-SHA256 AuthHeader s3.amazonaws.com TLSv1.2"
)


def test_parse_alb_line() -> None:
    p = parse_elb_line(ALB_LINE)
    assert p is not None
    assert p["kind"] == "https"
    assert p["client_ip"] == "203.0.113.66"
    assert p["status"] == "403"
    assert p["request"].startswith("GET https://shop.example.com")
    assert p["user_agent"] == "Mozilla/5.0"


def test_parse_classic_elb_line() -> None:
    p = parse_elb_line(CLB_LINE)
    assert p is not None
    assert p["kind"] == "classic"
    assert p["elb"] == "my-clb"
    assert p["status"] == "200"


def test_normalize_elb_alb_event() -> None:
    rec = {"line": ALB_LINE, "_ventra_region": "us-east-1", "_ventra_lb_name": "web-alb"}
    evs = list(normalize_elb_alb([rec], CTX))
    assert len(evs) == 1
    ev = evs[0]
    assert ev.ventra_source == "elb_alb"
    assert ev.event_action == "GET"
    assert ev.event_outcome == "failure"  # 403
    assert ev.source_ip == "203.0.113.66"
    assert "/admin/login" in ev.message
    assert ev.resource_id == "web-alb"


def test_normalize_cloudfront_event() -> None:
    p = parse_cloudfront_line(CF_LINE, CF_FIELDS)
    assert p is not None and p["sc-status"] == "404"
    rec = {"line": CF_LINE, "fields": CF_FIELDS, "_ventra_distribution_id": "E1ABC"}
    evs = list(normalize_cloudfront([rec], CTX))
    assert len(evs) == 1
    ev = evs[0]
    assert ev.timestamp == "2026-06-08T01:12:00Z"
    assert ev.event_outcome == "failure"
    assert ev.source_ip == "203.0.113.66"
    assert "/wp-admin/setup.php" in ev.message


def test_normalize_s3_access_event() -> None:
    p = parse_s3_access_line(S3_LINE)
    assert p is not None
    assert p["operation"] == "REST.GET.OBJECT"
    assert p["time"] == "2026-06-08T01:20:01Z"
    rec = {"line": S3_LINE, "_ventra_region": "us-east-1"}
    evs = list(normalize_s3_access([rec], CTX))
    assert len(evs) == 1
    ev = evs[0]
    assert ev.event_action == "REST.GET.OBJECT"
    assert ev.user_name == "dbadmin"
    assert ev.resource_id == "exfil-staging/customer-db.sql.gz"
    assert ev.event_outcome == "success"
    assert ev.dest_bytes == 1048576


def test_normalize_route53_resolver_event() -> None:
    rec = {
        "query_timestamp": "2026-06-08T01:15:30Z",
        "query_name": "evil-c2.example.net.",
        "query_type": "A",
        "rcode": "NOERROR",
        "answers": [{"Rdata": "198.51.100.7", "Type": "A", "Class": "IN"}],
        "srcaddr": "10.0.1.5",
        "vpc_id": "vpc-0abc",
        "region": "us-east-1",
        "srcids": {"instance": "i-0abc123"},
    }
    evs = list(normalize_route53_resolver([rec], CTX))
    assert len(evs) == 1
    ev = evs[0]
    assert ev.resource_id == "evil-c2.example.net"
    assert ev.dest_ip == "198.51.100.7"
    assert ev.event_outcome == "success"
    assert "i-0abc123" in ev.message

    nx = dict(rec, rcode="NXDOMAIN", answers=[])
    assert next(iter(normalize_route53_resolver([nx], CTX))).event_outcome == "failure"


def test_normalize_eks_audit_exec_is_high_severity() -> None:
    rec = {
        "kind": "Event",
        "stage": "ResponseComplete",
        "verb": "create",
        "user": {"username": "system:anonymous"},
        "sourceIPs": ["203.0.113.66"],
        "userAgent": "kubectl/v1.29",
        "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod", "name": "web-1"},
        "responseStatus": {"code": 101},
        "stageTimestamp": "2026-06-08T01:30:01Z",
        "annotations": {"authorization.k8s.io/decision": "allow"},
        "_ventra_cluster": "prod-cluster",
    }
    evs = list(normalize_eks_audit([rec], CTX))
    assert len(evs) == 1
    ev = evs[0]
    assert ev.event_severity == "high"  # exec into a pod
    assert ev.event_action == "create pods/exec"
    assert ev.user_name == "system:anonymous"
    assert "prod-cluster" in ev.message

    # RequestReceived stages are skipped (would duplicate every call).
    dup = dict(rec, stage="RequestReceived")
    assert list(normalize_eks_audit([dup], CTX)) == []

    denied = dict(rec, annotations={"authorization.k8s.io/decision": "forbid"})
    assert next(iter(normalize_eks_audit([denied], CTX))).event_outcome == "failure"


def test_normalize_inspector2_finding() -> None:
    rec = {
        "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/abc",
        "awsAccountId": "123456789012",
        "type": "PACKAGE_VULNERABILITY",
        "severity": "CRITICAL",
        "title": "CVE-2026-1234 - openssl",
        "updatedAt": "2026-06-08 01:00:00+00:00",
        "resources": [
            {
                "id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
                "type": "AWS_EC2_INSTANCE",
                "region": "us-east-1",
            }
        ],
        "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2026-1234"},
    }
    evs = list(normalize_inspector2([rec], CTX))
    assert len(evs) == 1
    ev = evs[0]
    assert ev.event_kind == "finding"
    assert ev.event_severity == "critical"
    assert ev.event_action == "CVE-2026-1234"
    assert ev.resource_id == "i-0abc"
    assert ev.ventra_source == "inspector2"
