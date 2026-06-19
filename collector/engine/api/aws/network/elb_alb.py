"""ELB / ALB access-log collector.

Load-balancer access logs are the web-attack reconstruction lens — client IPs, request
lines, status codes, and user agents for every request that crossed the edge. This collector
discovers every ALB/NLB (elbv2) and Classic ELB, records which ones have access logging
enabled and where it lands, then reads the log files from the S3 delivery buckets for the
case window. Load balancers WITHOUT access logging are recorded as gaps — a disabled access
log is itself evidence.

Raw log lines are shipped untouched (one record per line); the ingester owns parsing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from ..common.s3_logs import bucket_region, collect_s3_line_records, slash_day_prefixes

# Access logs default to the last 7 days unless --since/--until narrows or widens the window;
# edge logs are high-volume and, unlike CloudTrail, rarely matter beyond the intrusion window.
DEFAULT_WINDOW_DAYS = 7


def _parse_line_time(line: str) -> datetime | None:
    """Timestamp from an ELB access-log line. ALB/NLB: field 2; Classic ELB: field 1."""
    parts = line.split(" ", 2)
    for field in (parts[1] if len(parts) > 1 else "", parts[0]):
        if not field:
            continue
        try:
            return datetime.fromisoformat(field.replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


class ElbAlbCollector(Collector):
    name = "elb_alb"
    priority = 2
    description = "ELB/ALB access logs from S3 delivery buckets + per-LB logging posture."
    required_actions = (
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        window = self.ctx.time_window
        start = window.since or (datetime.now(UTC) - timedelta(days=DEFAULT_WINDOW_DAYS))
        end = window.until or datetime.now(UTC)

        lbs = self._discover_load_balancers(cf, gaps)
        if not lbs:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("elb_alb", GapReason.NOT_PRESENT, "No load balancers in scope.")],
                notes="No load balancers found.",
            )

        logging_on = [lb for lb in lbs if lb["access_logs_enabled"]]
        logging_off = [lb for lb in lbs if not lb["access_logs_enabled"]]
        if logging_off:
            names = ", ".join(lb["name"] for lb in logging_off[:10])
            more = f" (+{len(logging_off) - 10} more)" if len(logging_off) > 10 else ""
            gaps.append(
                (
                    "elb_alb",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"Access logging disabled on {len(logging_off)}/{len(lbs)} "
                    f"load balancer(s): {names}{more}.",
                )
            )

        records: list[dict] = []
        per_lb: list[dict] = []
        for lb in logging_on:
            self._log(f"Reading access logs for {lb['name']} ({lb['bucket']})…")
            recs, stats = self._read_lb_logs(cf, lb, start, end, gaps)
            records.extend(recs)
            per_lb.append({**lb, "records": len(recs), "objects_read": stats["objects_read"]})

        config = {
            "load_balancers": lbs,
            "logging_enabled_count": len(logging_on),
            "logging_disabled_count": len(logging_off),
            "collection": per_lb,
            "window": window.to_manifest(),
        }
        files = [self.write_json(config, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "load_balancers": len(lbs),
                "logging_enabled": len(logging_on),
                "window": window.to_manifest(),
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif logging_on:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(
                ("elb_alb", GapReason.NOT_PRESENT, "No access-log records in window.")
            )
        else:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} access-log lines from "
            f"{len(logging_on)}/{len(lbs)} load balancer(s) with logging enabled.",
        )

    def _discover_load_balancers(self, cf, gaps) -> list[dict[str, Any]]:
        """ALB/NLB (elbv2) + Classic ELB inventory with access-log attributes resolved."""
        out: list[dict[str, Any]] = []
        for region in self.ctx.regions:
            try:
                for lb in cf.paginate("elbv2", region, "describe_load_balancers", "LoadBalancers"):
                    arn = lb.get("LoadBalancerArn", "")
                    attrs = self._attrs_v2(cf, region, arn)
                    out.append(
                        {
                            "name": lb.get("LoadBalancerName", ""),
                            "arn": arn,
                            "type": lb.get("Type", "application"),
                            "region": region,
                            "dns_name": lb.get("DNSName", ""),
                            "access_logs_enabled": attrs.get("access_logs.s3.enabled") == "true",
                            "bucket": attrs.get("access_logs.s3.bucket", ""),
                            "prefix": attrs.get("access_logs.s3.prefix", ""),
                        }
                    )
            except AccessDenied as exc:
                gaps.append(("elb_alb", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except (ServiceNotEnabled, ClientError):
                pass
            try:
                for lb in cf.paginate(
                    "elb", region, "describe_load_balancers", "LoadBalancerDescriptions"
                ):
                    name = lb.get("LoadBalancerName", "")
                    al = self._attrs_classic(cf, region, name)
                    out.append(
                        {
                            "name": name,
                            "arn": "",
                            "type": "classic",
                            "region": region,
                            "dns_name": lb.get("DNSName", ""),
                            "access_logs_enabled": bool(al.get("Enabled")),
                            "bucket": al.get("S3BucketName", ""),
                            "prefix": al.get("S3BucketPrefix", ""),
                        }
                    )
            except (AccessDenied, ServiceNotEnabled, ClientError):
                pass
        return out

    @staticmethod
    def _attrs_v2(cf, region: str, arn: str) -> dict[str, str]:
        try:
            resp = cf.call(
                "elbv2", region, "describe_load_balancer_attributes", LoadBalancerArn=arn
            )
            return {a["Key"]: a.get("Value", "") for a in resp.get("Attributes", [])}
        except (AccessDenied, ServiceNotEnabled, ClientError):
            return {}

    @staticmethod
    def _attrs_classic(cf, region: str, name: str) -> dict[str, Any]:
        try:
            resp = cf.call(
                "elb", region, "describe_load_balancer_attributes", LoadBalancerName=name
            )
            return (resp.get("LoadBalancerAttributes") or {}).get("AccessLog") or {}
        except (AccessDenied, ServiceNotEnabled, ClientError):
            return {}

    def _read_lb_logs(
        self, cf, lb: dict[str, Any], start: datetime, end: datetime, gaps
    ) -> tuple[list[dict], dict]:
        bucket = lb["bucket"]
        prefix = (lb["prefix"] or "").strip("/")
        base = (
            f"{prefix}/AWSLogs/{self.ctx.account_id}/elasticloadbalancing/{lb['region']}/"
            if prefix
            else f"AWSLogs/{self.ctx.account_id}/elasticloadbalancing/{lb['region']}/"
        )
        region = bucket_region(cf, bucket, lb["region"])

        def line_to_record(key: str, line: str) -> dict[str, Any] | None:
            ts = _parse_line_time(line)
            if ts is not None and not (start <= ts <= end):
                return None
            return {
                "line": line,
                "_ventra_region": lb["region"],
                "_ventra_s3_bucket": bucket,
                "_ventra_log_key": key,
                "_ventra_lb_name": lb["name"],
                "_ventra_lb_type": lb["type"],
            }

        return collect_s3_line_records(
            cf,
            region,
            bucket,
            slash_day_prefixes(base, start, end),
            line_to_record,
            gaps,
            "elb_alb",
        )
