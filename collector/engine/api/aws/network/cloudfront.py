"""CloudFront access-log collector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_cloudfront_distributions
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from ..common.s3_logs import bucket_region, collect_s3_line_records, dash_day_prefixes

DEFAULT_WINDOW_DAYS = 7
MAX_DISTRIBUTIONS = 500
MAX_RECORDS = DEFAULT_MAX_RECORDS


class CloudFrontCollector(Collector):
    name = "cloudfront"
    priority = 2
    description = "CloudFront standard access logs from S3 + per-distribution logging posture."
    required_actions = (
        "cloudfront:ListDistributions",
        "cloudfront:GetDistributionConfig",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        cap = self.max_records(MAX_RECORDS)

        distributions = filter_cloudfront_distributions(self._discover_distributions(cf, gaps), params)
        if not distributions:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("cloudfront", GapReason.NOT_PRESENT, "No CloudFront distributions.")],
                notes="No CloudFront distributions found.",
            )

        logging_on = [d for d in distributions if d["logging_enabled"]]
        logging_off = [d for d in distributions if not d["logging_enabled"]]
        if logging_off:
            ids = ", ".join(d["id"] for d in logging_off[:10])
            gaps.append(
                (
                    "cloudfront",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"Standard logging disabled on {len(logging_off)}/{len(distributions)} "
                    f"distribution(s): {ids}.",
                )
            )

        per_dist: list[dict] = []
        record_count = 0
        event_files: list = []
        with self.open_jsonl("events.jsonl.gz") as writer:
            for dist in logging_on:
                self._log(f"Reading access logs for distribution {dist['id']}…")
                before = writer.count
                stats = self._read_dist_logs(
                    cf, dist, start, end, gaps, writer=writer, max_records=cap
                )
                per_dist.append(
                    {
                        **dist,
                        "records": writer.count - before,
                        "objects_read": stats["objects_read"],
                    }
                )
            record_count = writer.count
            if writer.count:
                event_files.append(writer.finalize())

        config = {
            "distributions": distributions,
            "logging_enabled_count": len(logging_on),
            "logging_disabled_count": len(logging_off),
            "collection": per_dist,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": params,
        }
        files = [self.write_json(config, "config.json"), *event_files]
        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "distributions": len(distributions),
                "logging_enabled": len(logging_on),
                "window": {"since": start.isoformat(), "until": end.isoformat()},
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif logging_on:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(
                ("cloudfront", GapReason.NOT_PRESENT, "No access-log records in window.")
            )
        else:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} access-log lines from "
            f"{len(logging_on)}/{len(distributions)} distribution(s) with logging enabled.",
        )

    def _discover_distributions(self, cf, gaps) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        token: str | None = None
        try:
            while len(out) < MAX_DISTRIBUTIONS:
                kwargs = {"Marker": token} if token else {}
                resp = cf.call("cloudfront", "us-east-1", "list_distributions", **kwargs)
                dl = resp.get("DistributionList") or {}
                for item in dl.get("Items") or []:
                    dist_id = item.get("Id", "")
                    logging = self._dist_logging(cf, dist_id)
                    out.append(
                        {
                            "id": dist_id,
                            "domain_name": item.get("DomainName", ""),
                            "aliases": (item.get("Aliases") or {}).get("Items") or [],
                            "logging_enabled": bool(logging.get("Enabled")),
                            "bucket": str(logging.get("Bucket") or "").removesuffix(
                                ".s3.amazonaws.com"
                            ),
                            "prefix": logging.get("Prefix", ""),
                        }
                    )
                if not dl.get("IsTruncated") or not dl.get("NextMarker"):
                    break
                token = dl["NextMarker"]
        except AccessDenied as exc:
            gaps.append(("cloudfront", GapReason.ACCESS_DENIED, exc.message))
        except (ServiceNotEnabled, ClientError):
            pass
        return out

    @staticmethod
    def _dist_logging(cf, dist_id: str) -> dict[str, Any]:
        try:
            resp = cf.call("cloudfront", "us-east-1", "get_distribution_config", Id=dist_id)
            return (resp.get("DistributionConfig") or {}).get("Logging") or {}
        except (AccessDenied, ServiceNotEnabled, ClientError):
            return {}

    def _read_dist_logs(
        self,
        cf,
        dist: dict[str, Any],
        start: datetime,
        end: datetime,
        gaps,
        *,
        writer=None,
        max_records: int = MAX_RECORDS,
    ) -> dict:
        bucket = dist["bucket"]
        base = f"{dist['prefix']}{dist['id']}."
        region = bucket_region(cf, bucket)
        current_fields: dict[str, str] = {"value": ""}

        def line_to_record(key: str, line: str) -> dict[str, Any] | None:
            if line.startswith("#Fields:"):
                current_fields["value"] = line[len("#Fields:") :].strip()
                return None
            if line.startswith("#"):
                return None
            ts = _w3c_time(line)
            if ts is not None and not (start <= ts <= end):
                return None
            return {
                "line": line,
                "fields": current_fields["value"],
                "_ventra_region": "global",
                "_ventra_s3_bucket": bucket,
                "_ventra_log_key": key,
                "_ventra_distribution_id": dist["id"],
                "_ventra_domain_name": dist["domain_name"],
            }

        _, stats = collect_s3_line_records(
            cf,
            region,
            bucket,
            dash_day_prefixes(base, start, end),
            line_to_record,
            gaps,
            "cloudfront",
            max_records=max_records,
            writer=writer,
        )
        return stats


def _w3c_time(line: str) -> datetime | None:
    parts = line.split("\t", 2)
    if len(parts) < 2:
        return None
    try:
        return datetime.fromisoformat(f"{parts[0]}T{parts[1]}+00:00")
    except ValueError:
        return None
