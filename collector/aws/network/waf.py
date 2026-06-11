"""AWS WAF (WAFv2) collector.

Captures Web ACL configurations, their logging configuration (often disabled — a gap), and a
sample of recent requests via GetSampledRequests. Web ACLs exist at two scopes: regional
(ALB/API Gateway) and CLOUDFRONT (global, queried in us-east-1).

GetSampledRequests can only see the previous three hours, so the sample reflects traffic at
collection time — still valuable during an active incident. WAFv2 List* operations have no
botocore paginators; pagination is manual via NextMarker.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled

# GetSampledRequests API maximum.
MAX_SAMPLED_REQUESTS = 500


class WafCollector(Collector):
    name = "waf"
    tier = 1
    description = "WAFv2 Web ACL configs, logging configuration, sampled requests."
    required_actions = (
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:GetLoggingConfiguration",
        "wafv2:GetSampledRequests",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        acls: list[dict] = []
        samples: list[dict] = []

        scopes = [("REGIONAL", r) for r in self.ctx.regions] + [("CLOUDFRONT", "us-east-1")]
        for scope, region in scopes:
            try:
                listed = list(
                    cf.paginate_manual(
                        "wafv2",
                        region,
                        "list_web_acls",
                        "WebACLs",
                        token_request_key="NextMarker",
                        token_response_key="NextMarker",
                        Scope=scope,
                    )
                )
            except AccessDenied as exc:
                gaps.append(("waf", GapReason.ACCESS_DENIED, f"{scope}/{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue
            for summary in listed:
                acl = {"scope": scope, "region": region, "summary": summary}
                try:
                    acl["detail"] = cf.call(
                        "wafv2", region, "get_web_acl",
                        Name=summary["Name"], Scope=scope, Id=summary["Id"],
                    ).get("WebACL", {})
                    acl["logging"] = cf.call(
                        "wafv2", region, "get_logging_configuration",
                        ResourceArn=summary["ARN"],
                    ).get("LoggingConfiguration", {})
                except ServiceNotEnabled:
                    acl["logging"] = None  # logging not enabled — a gap noted below
                except AccessDenied:
                    pass
                samples.extend(self._sampled_requests(cf, region, scope, acl))
                acls.append(acl)

        if not acls:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("waf", GapReason.NOT_PRESENT, "No WAFv2 Web ACLs in scope.")],
                notes="No WAF Web ACLs found.",
            )

        if any(a.get("logging") in (None, {}) for a in acls):
            gaps.append(
                ("waf_logging", GapReason.LOGGING_NOT_CONFIGURED,
                 "One or more Web ACLs have no logging configuration.")
            )

        files = [self.write_json({"web_acls": acls}, "config.json")]
        if samples:
            files.append(self.write_jsonl(samples, "events.jsonl.gz"))
        self.write_meta(
            {"source": self.name, "web_acls": len(acls), "sampled_requests": len(samples)}
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(acls),
            gaps=gaps,
            notes=f"{len(acls)} Web ACL(s); {len(samples)} sampled request(s).",
        )

    def _sampled_requests(self, cf, region: str, scope: str, acl: dict) -> list[dict]:
        """Sample recent requests per rule metric. The API only covers the last 3 hours and
        only returns data where VisibilityConfig.SampledRequestsEnabled is true."""
        detail = acl.get("detail") or {}
        arn = (acl.get("summary") or {}).get("ARN") or detail.get("ARN")
        if not arn:
            return []

        metrics: list[str] = []
        top_vis = detail.get("VisibilityConfig") or {}
        if top_vis.get("SampledRequestsEnabled") and top_vis.get("MetricName"):
            metrics.append(top_vis["MetricName"])
        for rule in detail.get("Rules") or []:
            vis = rule.get("VisibilityConfig") or {}
            if vis.get("SampledRequestsEnabled") and vis.get("MetricName"):
                metrics.append(vis["MetricName"])

        end = datetime.now(UTC)
        start = end - timedelta(hours=3)
        out: list[dict] = []
        for metric in dict.fromkeys(metrics):  # dedupe, keep order
            try:
                resp = cf.call(
                    "wafv2", region, "get_sampled_requests",
                    WebAclArn=arn,
                    RuleMetricName=metric,
                    Scope=scope,
                    TimeWindow={"StartTime": start, "EndTime": end},
                    MaxItems=MAX_SAMPLED_REQUESTS,
                )
            except Exception:  # noqa: BLE001 - sampling is best-effort enrichment
                continue
            for req in resp.get("SampledRequests") or []:
                req["_harbor_region"] = region
                req["_harbor_web_acl_arn"] = arn
                req["_harbor_rule_metric"] = metric
                out.append(req)
        return out
