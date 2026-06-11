"""KMS collector (Tier 2).

Key inventory with key policies and grants. Key-policy changes and broad grants are
privilege-escalation and exfil enablers (decrypting data you shouldn't). Actual key-usage
events come from CloudTrail; here we capture the configuration state.
"""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class KmsCollector(Collector):
    name = "kms"
    tier = 2
    description = "KMS key inventory, key policies, and grants."
    required_actions = (
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:ListGrants",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        keys: list[dict] = []

        for region in self.ctx.regions:
            try:
                key_ids = [k["KeyId"] for k in cf.paginate("kms", region, "list_keys", "Keys")]
            except AccessDenied as exc:
                gaps.append(("kms", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue
            for kid in key_ids:
                entry: dict = {"region": region, "key_id": kid}
                try:
                    entry["metadata"] = cf.call("kms", region, "describe_key", KeyId=kid).get(
                        "KeyMetadata", {}
                    )
                    # Skip AWS-managed keys' policies (not customer-relevant, and noisy).
                    if entry["metadata"].get("KeyManager") == "CUSTOMER":
                        entry["policy"] = cf.call(
                            "kms", region, "get_key_policy", KeyId=kid, PolicyName="default"
                        ).get("Policy")
                        entry["grants"] = list(
                            cf.paginate("kms", region, "list_grants", "Grants", KeyId=kid)
                        )
                except (AccessDenied, ServiceNotEnabled):
                    pass
                keys.append(entry)

        if not keys:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("kms", GapReason.NOT_PRESENT, "No KMS keys in scope.")],
                notes="No KMS keys found.",
            )

        wf = self.write_json({"keys": keys}, "snapshot.json")
        self.write_meta({"source": self.name, "keys": len(keys)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            record_count=len(keys),
            gaps=gaps,
            notes=f"{len(keys)} key(s).",
        )
