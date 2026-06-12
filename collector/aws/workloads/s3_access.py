"""S3 server access-log collector.

Server access logs are the object-level lens on S3 — who fetched which key, from which IP,
with which credentials — and often the only record of data staging/exfil from a bucket when
CloudTrail data events were never enabled. This collector maps every bucket's logging
target, reads the log files from the target buckets for the case window, and records
buckets WITHOUT access logging as gaps.

Raw lines are shipped untouched; the ingester owns parsing.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled
from ..common.s3_logs import bucket_region, collect_s3_line_records, dash_day_prefixes

DEFAULT_WINDOW_DAYS = 7

_TIME_RE = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})")


def _parse_line_time(line: str) -> datetime | None:
    m = _TIME_RE.search(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


class S3AccessCollector(Collector):
    name = "s3_access"
    priority = 2
    description = "S3 server access logs from logging target buckets + per-bucket posture."
    required_actions = (
        "s3:ListAllMyBuckets",
        "s3:GetBucketLogging",
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

        try:
            buckets = [
                b.get("Name", "")
                for b in cf.call("s3", None, "list_buckets").get("Buckets", [])
            ]
        except AccessDenied as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.ERRORED,
                gaps=[("s3_access", GapReason.ACCESS_DENIED, exc.message)],
                notes="Could not list buckets.",
            )
        except (ServiceNotEnabled, ClientError) as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.ERRORED,
                gaps=[("s3_access", GapReason.COLLECTOR_ERROR, str(exc))],
                notes="Could not list buckets.",
            )

        if not buckets:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("s3_access", GapReason.NOT_PRESENT, "No S3 buckets in account.")],
                notes="No buckets.",
            )

        # destination (target_bucket, target_prefix) -> source buckets logging there.
        destinations: dict[tuple[str, str], list[str]] = {}
        unlogged: list[str] = []
        for bucket in buckets:
            target = self._logging_target(cf, bucket)
            if target:
                destinations.setdefault(target, []).append(bucket)
            else:
                unlogged.append(bucket)

        if unlogged:
            names = ", ".join(unlogged[:10])
            more = f" (+{len(unlogged) - 10} more)" if len(unlogged) > 10 else ""
            gaps.append(
                (
                    "s3_access",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"Server access logging disabled on {len(unlogged)}/{len(buckets)} "
                    f"bucket(s): {names}{more}.",
                )
            )

        records: list[dict] = []
        per_dest: list[dict] = []
        for (target_bucket, target_prefix), source_buckets in destinations.items():
            self._log(f"Reading access logs from {target_bucket}/{target_prefix}…")
            region = bucket_region(cf, target_bucket)

            def line_to_record(
                key: str, line: str, _tb: str = target_bucket, _region: str = region
            ) -> dict[str, Any] | None:
                ts = _parse_line_time(line)
                if ts is not None and not (start <= ts <= end):
                    return None
                return {
                    "line": line,
                    "_ventra_region": _region,
                    "_ventra_s3_bucket": _tb,
                    "_ventra_log_key": key,
                }

            recs, stats = collect_s3_line_records(
                cf,
                region,
                target_bucket,
                dash_day_prefixes(target_prefix, start, end),
                line_to_record,
                gaps,
                "s3_access",
            )
            records.extend(recs)
            per_dest.append(
                {
                    "target_bucket": target_bucket,
                    "target_prefix": target_prefix,
                    "source_buckets": source_buckets,
                    "records": len(recs),
                    "objects_read": stats["objects_read"],
                }
            )

        config = {
            "buckets_total": len(buckets),
            "buckets_logged": len(buckets) - len(unlogged),
            "buckets_unlogged": unlogged,
            "destinations": per_dest,
            "window": window.to_manifest(),
        }
        files = [self.write_json(config, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "buckets_total": len(buckets),
                "buckets_logged": len(buckets) - len(unlogged),
                "window": window.to_manifest(),
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif destinations:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(
                ("s3_access", GapReason.NOT_PRESENT, "No access-log records in window.")
            )
        else:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} access-log lines; "
            f"{len(buckets) - len(unlogged)}/{len(buckets)} bucket(s) logged.",
        )

    @staticmethod
    def _logging_target(cf, bucket: str) -> tuple[str, str] | None:
        try:
            resp = cf.call("s3", None, "get_bucket_logging", Bucket=bucket)
        except (AccessDenied, ServiceNotEnabled, ClientError):
            return None
        enabled = resp.get("LoggingEnabled") or {}
        target = enabled.get("TargetBucket")
        if not target:
            return None
        return (target, enabled.get("TargetPrefix", ""))
