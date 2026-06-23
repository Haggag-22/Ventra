"""Security Hub collector (extended collector).

Security Hub aggregates findings from GuardDuty, Inspector, Macie, and partner products into
a single ASFF feed. Collecting it gives the console's Findings panel a deduped, cross-service
view. Captures enabled standards plus active findings within the window.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled

from collector.lib.limits import records_unlimited


class SecurityHubCollector(Collector):
    name = "securityhub"
    priority = 2
    description = "Security Hub findings (ASFF) and enabled standards."
    required_actions = (
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:GetFindings",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        findings: list[dict] = []
        standards: list[dict] = []
        enabled_anywhere = False

        truncated = False
        cap = self.max_records()
        for region in self.ctx.regions:
            try:
                cf.call("securityhub", region, "describe_hub")
                enabled_anywhere = True
            except (AccessDenied, ServiceNotEnabled):
                continue
            except ClientError as exc:
                gaps.append(("securityhub", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
                continue
            try:
                standards.extend(
                    cf.call("securityhub", region, "get_enabled_standards").get(
                        "StandardsSubscriptions", []
                    )
                )
                for f in cf.paginate(
                    "securityhub", region, "get_findings", "Findings",
                    Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
                    MaxResults=100,
                ):
                    if not records_unlimited(cap) and len(findings) >= cap:
                        truncated = True
                        break
                    f["_ventra_region"] = region
                    findings.append(f)
            except AccessDenied as exc:
                gaps.append(("securityhub", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except ServiceNotEnabled:
                continue
            except ClientError as exc:
                gaps.append(("securityhub", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
                continue
            if truncated:
                gaps.append(
                    (
                        "securityhub",
                        GapReason.COLLECTOR_ERROR,
                        f"Findings truncated at {cap:,}; export the rest from "
                        "Security Hub directly if full coverage is required.",
                    )
                )
                break

        if not enabled_anywhere:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("securityhub", GapReason.SERVICE_NOT_ENABLED, "Security Hub not enabled.")],
                notes="Security Hub not enabled.",
            )

        files = [self.write_json({"standards": standards}, "config.json")]
        if findings:
            files.append(self.write_jsonl(findings, "events.jsonl.gz"))
        self.write_meta({"source": self.name, "findings": len(findings)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(findings),
            gaps=gaps,
            notes=f"{len(findings)} active findings.",
        )
