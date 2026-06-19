"""Read VPC Flow Log records from their S3 delivery bucket.

The VPC Flow Logs collector pulls records directly from CloudWatch Logs when the flow log
delivers there. The far more common production layout delivers to S3 instead — this module
reads those S3-resident records so the Network panel can quantify egress/rejects regardless
of the delivery destination.

Only the default *plain-text* file format is parsed (gzipped ``.log.gz`` with a header row).
Parquet / Hive-partitioned deliveries are reported as a gap rather than parsed, since that
would pull in a heavy parquet dependency unsuitable for a constrained cloud shell.
"""

from __future__ import annotations

import gzip
import io
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from collector.lib.models import GapReason
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled

# Keep CloudShell runs bounded.
MAX_LOG_OBJECTS = 2000
MAX_RECORDS = 200_000

# Map plain-text flow-log header tokens to the keys the vpc_flow normalizer expects.
# AWS emits the header as the field names with hyphens (e.g. ``account-id``); the normalizer
# keys use underscores. Tokens not listed here pass through unchanged.
_HEADER_KEY_MAP = {
    "account-id": "account_id",
    "interface-id": "interface_id",
    "log-status": "log_status",
}


def flow_log_s3_target(flow_log: dict[str, Any]) -> tuple[str, str] | None:
    """Return ``(bucket, prefix)`` for an S3-delivering flow log, else ``None``.

    ``LogDestination`` is an S3 ARN like ``arn:aws:s3:::my-bucket/some/prefix/``. The prefix
    is optional and a custom prefix is *prepended* to the AWSLogs/ tree.
    """
    if flow_log.get("LogDestinationType") != "s3":
        return None
    arn = (flow_log.get("LogDestination") or "").strip()
    if not arn.startswith("arn:aws:s3:::"):
        return None
    path = arn[len("arn:aws:s3:::"):]
    bucket, _, prefix = path.partition("/")
    if not bucket:
        return None
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return bucket, prefix


def _iter_days(start: datetime, end: datetime):
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    last = end.replace(hour=0, minute=0, second=0, microsecond=0)
    while day <= last:
        yield day
        day += timedelta(days=1)


def _day_prefixes(
    prefix: str, account_id: str, region: str, start: datetime, end: datetime
) -> list[str]:
    """Daily key prefixes, e.g. ``<prefix>AWSLogs/<acct>/vpcflowlogs/<region>/2026/06/15/``."""
    base = f"{prefix}AWSLogs/{account_id}/vpcflowlogs/{region}"
    return [f"{base}/{d.year:04d}/{d.month:02d}/{d.day:02d}/" for d in _iter_days(start, end)]


def _parse_plaintext(body: bytes, region: str) -> list[dict[str, Any]]:
    """Parse a gzipped plain-text flow-log object into structured records.

    The first line is the space-delimited header naming each field; subsequent lines hold the
    values. Records that carry no flow (NODATA/SKIPDATA, or '-' addresses) are dropped.
    """
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
        text = gz.read().decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) < 2:
        return []
    header = [_HEADER_KEY_MAP.get(tok, tok) for tok in lines[0].split()]
    out: list[dict[str, Any]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split()
        if len(values) != len(header):
            continue
        rec = dict(zip(header, values, strict=True))
        action = (rec.get("action") or "").upper()
        if action not in ("ACCEPT", "REJECT"):
            continue
        if rec.get("srcaddr") in (None, "", "-") or rec.get("dstaddr") in (None, "", "-"):
            continue
        rec["_ventra_region"] = region
        out.append(rec)
    return out


def _in_window(rec: dict[str, Any], start: datetime, end: datetime) -> bool:
    raw = rec.get("start")
    if not raw:
        return True  # keep records without a parseable timestamp; day-prefix already bounds them
    try:
        ts = datetime.fromtimestamp(int(raw), tz=UTC)
    except (ValueError, OSError, TypeError):
        return True
    return start <= ts <= end


def collect_s3_flow_records(
    cf,
    flow_log: dict[str, Any],
    account_id: str,
    start: datetime,
    end: datetime,
    gaps: list[tuple[str, GapReason, str]],
    *,
    log: Callable[[str], None] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull flow records for one S3-delivering flow log within the time window."""
    region = flow_log.get("_ventra_region") or ""
    stats: dict[str, Any] = {
        "objects_scanned": 0,
        "objects_read": 0,
        "records": 0,
        "bucket": "",
        "region": region,
        "truncated": False,
        "unsupported_format": False,
    }
    target = flow_log_s3_target(flow_log)
    if not target or not region:
        return [], stats
    bucket, prefix = target
    stats["bucket"] = bucket

    fmt = ((flow_log.get("DestinationOptions") or {}).get("FileFormat") or "plain-text").lower()
    if fmt != "plain-text":
        stats["unsupported_format"] = True
        gaps.append(
            (
                "vpc_flow_s3",
                GapReason.NOT_PRESENT,
                f"{bucket}: flow logs delivered as '{fmt}' (only plain-text is parsed); "
                "records were not ingested.",
            )
        )
        return [], stats

    records: list[dict[str, Any]] = []
    s3 = cf.client("s3", region)

    try:
        for prefix_key in _day_prefixes(prefix, account_id, region, start, end):
            if stats["objects_scanned"] >= MAX_LOG_OBJECTS or stats["truncated"]:
                stats["truncated"] = True
                break
            try:
                for obj in cf.paginate(
                    "s3", region, "list_objects_v2", "Contents", Bucket=bucket, Prefix=prefix_key
                ):
                    stats["objects_scanned"] += 1
                    if stats["objects_scanned"] > MAX_LOG_OBJECTS:
                        stats["truncated"] = True
                        break
                    key = obj.get("Key", "")
                    if not key.endswith(".log.gz"):
                        continue
                    stats["objects_read"] += 1
                    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                    for rec in _parse_plaintext(body, region):
                        if len(records) >= MAX_RECORDS:
                            stats["truncated"] = True
                            break
                        if not _in_window(rec, start, end):
                            continue
                        rec["_ventra_log_key"] = key
                        rec["_ventra_s3_bucket"] = bucket
                        rec["_ventra_collect_source"] = "s3_logs"
                        records.append(rec)
                        stats["records"] += 1
                    if stats["truncated"]:
                        break
            except AccessDenied as exc:
                gaps.append(
                    ("vpc_flow_s3", GapReason.ACCESS_DENIED, f"{bucket}/{prefix_key}: {exc.message}")
                )
            except ServiceNotEnabled:
                continue
    except AccessDenied as exc:
        gaps.append(("vpc_flow_s3", GapReason.ACCESS_DENIED, f"{bucket}: {exc.message}"))

    if log and stats["records"]:
        log(f"S3 {bucket}: {stats['records']} flow records ({stats['objects_read']} objects)")
    return records, stats
