"""Account & organization context collector.

Captures the environment the rest of the evidence is interpreted against: account id/alias,
org placement, enabled regions, and the operator identity that ran the collection. This is
baseline and effectively free.
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled


class AccountCollector(Collector):
    name = "account"
    priority = 1
    description = "Account, organization, region, and operator context."
    required_actions = (
        "sts:GetCallerIdentity",
        "iam:ListAccountAliases",
        "organizations:DescribeOrganization",
        "ec2:DescribeRegions",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        identity = cf.caller_identity()
        snapshot = {
            "account_id": identity.account_id,
            "operator_arn": identity.arn,
            "operator_user_id": identity.user_id,
            "partition": identity.partition,
            "regions_in_scope": self.ctx.regions,
        }

        # Account alias (best-effort).
        try:
            aliases = list(cf.paginate("iam", None, "list_account_aliases", "AccountAliases"))
            snapshot["account_alias"] = aliases[0] if aliases else ""
        except (AccessDenied, ServiceNotEnabled):
            snapshot["account_alias"] = ""

        # Organization placement (best-effort; standalone accounts have none).
        gaps: list[tuple[str, GapReason, str]] = []
        try:
            org = cf.call("organizations", None, "describe_organization").get("Organization", {})
            snapshot["org_id"] = org.get("Id", "")
            snapshot["org_master_account"] = org.get("MasterAccountId", "")
        except AccessDenied as exc:
            snapshot["org_id"] = ""
            gaps.append(("organizations", GapReason.ACCESS_DENIED, exc.message))
        except ServiceNotEnabled:
            snapshot["org_id"] = ""

        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "account_id": identity.account_id,
                "regions": self.ctx.regions,
                "sha256": wf.sha256,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes="Environment + operator context.",
        )
