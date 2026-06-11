"""S3 surface collector (Tier 2).

The bucket attack surface: which buckets exist, which are public or have permissive ACLs,
their bucket policies, whether access logging is on, and Object Lock / public-access-block
state. This is the storage exfil lens; actual object-access events come from CloudTrail data
events / S3 server access logs delivered to a log bucket.
"""

from __future__ import annotations

from ...common.base import Collector
from ...common.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class S3Collector(Collector):
    name = "s3"
    tier = 2
    description = "S3 bucket inventory, public-exposure, policies, logging, Object Lock."
    required_actions = (
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketObjectLockConfiguration",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        try:
            buckets = cf.call("s3", None, "list_buckets").get("Buckets", [])
        except AccessDenied as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.ERRORED,
                gaps=[("s3", GapReason.ACCESS_DENIED, exc.message)],
                errors=[str(exc)],
            )

        records = []
        public_count = 0
        for b in buckets:
            name = b["Name"]
            entry: dict = {"name": name, "creation_date": b.get("CreationDate")}
            entry["region"] = self._safe(cf, "get_bucket_location", name, "LocationConstraint")
            entry["acl"] = self._safe(cf, "get_bucket_acl", name, "Grants")
            entry["policy"] = self._safe(cf, "get_bucket_policy", name, "Policy")
            entry["policy_status"] = self._safe(cf, "get_bucket_policy_status", name, "PolicyStatus")
            entry["logging"] = self._safe(cf, "get_bucket_logging", name, "LoggingEnabled")
            entry["public_access_block"] = self._safe(
                cf, "get_public_access_block", name, "PublicAccessBlockConfiguration"
            )
            entry["object_lock"] = self._safe(
                cf, "get_object_lock_configuration", name, "ObjectLockConfiguration"
            )
            if isinstance(entry.get("policy_status"), dict) and entry["policy_status"].get("IsPublic"):
                public_count += 1
                entry["_harbor_public"] = True
            if not entry.get("logging"):
                entry["_harbor_no_access_logging"] = True
            records.append(entry)

        if public_count:
            gaps.append(
                ("s3_public", GapReason.NOT_PRESENT,
                 f"{public_count} bucket(s) evaluate as public — review for exposure/exfil.")
            )

        wf = self.write_json({"buckets": records}, "snapshot.json")
        self.write_meta({"source": self.name, "buckets": len(records), "public": public_count})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} bucket(s), {public_count} public.",
        )

    def _safe(self, cf, op, bucket, key):
        try:
            return cf.call("s3", None, op, Bucket=bucket).get(key)
        except (AccessDenied, ServiceNotEnabled):
            return None
        except Exception:
            return None
