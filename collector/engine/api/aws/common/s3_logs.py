"""Bounded reader for S3-delivered line-format service logs (ELB, CloudFront, S3 access).

Mirrors the CloudTrail S3 path: list day-scoped prefixes, read objects (gzip or plain),
yield records, count everything, and translate access errors into manifest gaps instead of
crashes. Collectors ship raw lines; the ingester owns versioned parsing.
"""

from __future__ import annotations

import gzip
import io
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta
from typing import Any

from collector.lib.models import GapReason
from collector.clouds.aws.client_factory import AccessDenied

# Keep CloudShell runs bounded.
MAX_LOG_OBJECTS = 2000
MAX_RECORDS = 200_000

# (key, line) -> record dict, or None to skip (comment line / out of window).
LineToRecord = Callable[[str, str], dict[str, Any] | None]


def iter_days(start: datetime, end: datetime) -> Iterator[datetime]:
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    last = end.replace(hour=0, minute=0, second=0, microsecond=0)
    while day <= last:
        yield day
        day += timedelta(days=1)


def slash_day_prefixes(base: str, start: datetime, end: datetime) -> list[str]:
    """``<base>YYYY/MM/DD/`` layout (ELB, Route53 Resolver to S3)."""
    return [f"{base}{d.year:04d}/{d.month:02d}/{d.day:02d}/" for d in iter_days(start, end)]


def dash_day_prefixes(base: str, start: datetime, end: datetime) -> list[str]:
    """``<base>YYYY-MM-DD`` flat layout (CloudFront, S3 server access logs)."""
    return [f"{base}{d.year:04d}-{d.month:02d}-{d.day:02d}" for d in iter_days(start, end)]


def bucket_region(cf, bucket: str, default: str = "us-east-1") -> str:
    """Best-effort bucket region so cross-region log buckets still list correctly."""
    try:
        loc = cf.call("s3", default, "get_bucket_location", Bucket=bucket)
        return loc.get("LocationConstraint") or "us-east-1"
    except Exception:  # noqa: BLE001 - region resolution is an optimization, not a requirement
        return default


def _object_lines(body: bytes, key: str) -> Iterator[str]:
    if key.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
            text = gz.read().decode("utf-8", errors="replace")
    else:
        text = body.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if line.strip():
            yield line


def collect_s3_line_records(
    cf,
    region: str,
    bucket: str,
    prefixes: list[str],
    line_to_record: LineToRecord,
    gaps: list[tuple[str, GapReason, str]],
    gap_name: str,
    *,
    max_objects: int = MAX_LOG_OBJECTS,
    max_records: int = MAX_RECORDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read line logs under ``prefixes`` in ``bucket``; returns (records, stats)."""
    stats: dict[str, Any] = {
        "bucket": bucket,
        "objects_scanned": 0,
        "objects_read": 0,
        "records": 0,
        "truncated": False,
    }
    records: list[dict[str, Any]] = []
    s3 = cf.client("s3", region)

    for prefix in prefixes:
        if stats["truncated"]:
            break
        try:
            for obj in cf.paginate(
                "s3", region, "list_objects_v2", "Contents", Bucket=bucket, Prefix=prefix
            ):
                stats["objects_scanned"] += 1
                if stats["objects_scanned"] > max_objects:
                    stats["truncated"] = True
                    break
                key = obj.get("Key", "")
                if key.endswith("/"):
                    continue
                try:
                    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                except Exception as exc:  # noqa: BLE001 - one unreadable object is a gap, not a crash
                    gaps.append((gap_name, GapReason.COLLECTOR_ERROR, f"{bucket}/{key}: {exc}"))
                    continue
                stats["objects_read"] += 1
                for line in _object_lines(body, key):
                    if len(records) >= max_records:
                        stats["truncated"] = True
                        break
                    rec = line_to_record(key, line)
                    if rec is not None:
                        records.append(rec)
                        stats["records"] += 1
                if stats["truncated"]:
                    break
        except AccessDenied as exc:
            gaps.append((gap_name, GapReason.ACCESS_DENIED, f"{bucket}/{prefix}: {exc.message}"))

    if stats["truncated"]:
        gaps.append(
            (
                gap_name,
                GapReason.COLLECTOR_ERROR,
                f"{bucket}: truncated at {max_objects} objects / {max_records} records; "
                "narrow the window (--since/--until) for full coverage.",
            )
        )
    return records, stats
