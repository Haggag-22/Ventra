"""S3 surface collector (extended collector).

The bucket attack surface: which buckets exist, which are public or have permissive ACLs,
their bucket policies, whether access logging is on, and Object Lock / public-access-block
state. This is the storage exfil lens; actual object-access events come from CloudTrail data
events / S3 server access logs delivered to a log bucket.
"""

from __future__ import annotations

from botocore.exceptions import OperationNotPageableError

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled


def _normalize_location(constraint: str | None) -> str:
    """GetBucketLocation quirks: us-east-1 reports null, eu-west-1 may report ``EU``."""
    if not constraint:
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    return constraint


class S3Collector(Collector):
    name = "s3"
    priority = 2
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
            # Paginated: accounts can exceed ListBuckets' single-response limit. Older
            # botocore releases have no ListBuckets paginator — fall back to one call.
            try:
                buckets = list(cf.paginate("s3", None, "list_buckets", "Buckets"))
            except OperationNotPageableError:
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
            # Resolve the bucket's region first and address it there directly, so the
            # per-bucket calls don't depend on cross-region redirect behaviour.
            location = self._safe(cf, "get_bucket_location", name, "LocationConstraint")
            region = _normalize_location(location)
            entry["region"] = region
            entry["acl"] = self._safe(cf, "get_bucket_acl", name, "Grants", region)
            entry["policy"] = self._safe(cf, "get_bucket_policy", name, "Policy", region)
            entry["policy_status"] = self._safe(
                cf, "get_bucket_policy_status", name, "PolicyStatus", region
            )
            entry["logging"] = self._safe(cf, "get_bucket_logging", name, "LoggingEnabled", region)
            entry["public_access_block"] = self._safe(
                cf, "get_public_access_block", name, "PublicAccessBlockConfiguration", region
            )
            entry["object_lock"] = self._safe(
                cf, "get_object_lock_configuration", name, "ObjectLockConfiguration", region
            )
            if isinstance(entry.get("policy_status"), dict) and entry["policy_status"].get("IsPublic"):
                public_count += 1
                entry["_ventra_public"] = True
            if not entry.get("logging"):
                entry["_ventra_no_access_logging"] = True
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

    def _safe(self, cf, op, bucket, key, region=None):
        try:
            return cf.call("s3", region, op, Bucket=bucket).get(key)
        except (AccessDenied, ServiceNotEnabled):
            return None
        except Exception:
            return None
