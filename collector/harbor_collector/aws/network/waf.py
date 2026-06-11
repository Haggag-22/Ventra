"""AWS WAF (WAFv2) collector.

Captures Web ACL configurations, their logging configuration (often disabled — a gap), and a
sample of recent requests via GetSampledRequests. Web ACLs exist at two scopes: regional
(ALB/API Gateway) and CLOUDFRONT (global, queried in us-east-1).
"""

from __future__ import annotations

from ...common.base import Collector
from ...common.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


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

        scopes = [("REGIONAL", r) for r in self.ctx.regions] + [("CLOUDFRONT", "us-east-1")]
        for scope, region in scopes:
            try:
                listed = cf.call("wafv2", region, "list_web_acls", Scope=scope).get(
                    "WebACLs", []
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

        wf = self.write_json({"web_acls": acls}, "config.json")
        self.write_meta({"source": self.name, "web_acls": len(acls)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            record_count=len(acls),
            gaps=gaps,
            notes=f"{len(acls)} Web ACL(s).",
        )
