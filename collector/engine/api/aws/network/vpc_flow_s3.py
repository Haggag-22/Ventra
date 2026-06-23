"""Read VPC Flow Log records from their S3 delivery bucket."""

from __future__ import annotations

import gzip
import io
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from collector.lib.limits import (
    DEFAULT_MAX_LOG_OBJECTS,
    DEFAULT_MAX_RECORDS,
    records_unlimited,
    resolve_max_objects,
)
from collector.lib.models import GapReason
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled

if TYPE_CHECKING:
    from collector.lib.base import JsonlWriter

MAX_LOG_OBJECTS = DEFAULT_MAX_LOG_OBJECTS
MAX_RECORDS = DEFAULT_MAX_RECORDS

_HEADER_KEY_MAP = {
    "account-id": "account_id",
    "interface-id": "interface_id",
    "log-status": "log_status",
}


def flow_log_s3_target(flow_log: dict[str, Any]) -> tuple[str, str] | None:
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
    base = f"{prefix}AWSLogs/{account_id}/vpcflowlogs/{region}"
    return [f"{base}/{d.year:04d}/{d.month:02d}/{d.day:02d}/" for d in _iter_days(start, end)]


def _flow_scope_tags(flow_log: dict[str, Any]) -> dict[str, str]:
    rid = (flow_log.get("ResourceId") or "").strip()
    if rid.startswith("vpc-"):
        return {"_ventra_vpc_id": rid}
    if rid:
        return {"_ventra_flow_resource_id": rid}
    return {}


def _iter_plaintext_records(body: bytes, region: str, extra: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
        text = gz.read().decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) < 2:
        return
    header = [_HEADER_KEY_MAP.get(tok, tok) for tok in lines[0].split()]
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
        if extra:
            rec.update(extra)
        yield rec


def _in_window(rec: dict[str, Any], start: datetime, end: datetime) -> bool:
    raw = rec.get("start")
    if not raw:
        return True
    try:
        ts = datetime.fromtimestamp(int(raw), tz=UTC)
    except (ValueError, OSError, TypeError):
        return True
    return start <= ts <= end


def _written_count(writer: JsonlWriter | None, records: list[dict[str, Any]]) -> int:
    return writer.count if writer is not None else len(records)


def collect_s3_flow_records(
    cf,
    flow_log: dict[str, Any],
    account_id: str,
    start: datetime,
    end: datetime,
    gaps: list[tuple[str, GapReason, str]],
    *,
    log: Callable[[str], None] | None = None,
    max_records: int = MAX_RECORDS,
    max_objects: int | None = None,
    writer: JsonlWriter | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull flow records for one S3-delivering flow log within the time window."""
    region = flow_log.get("_ventra_region") or ""
    obj_cap = resolve_max_objects(max_records, max_objects)
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
    scope_tags = _flow_scope_tags(flow_log)

    try:
        for prefix_key in _day_prefixes(prefix, account_id, region, start, end):
            if stats["truncated"]:
                break
            try:
                for obj in cf.paginate(
                    "s3", region, "list_objects_v2", "Contents", Bucket=bucket, Prefix=prefix_key
                ):
                    stats["objects_scanned"] += 1
                    if not records_unlimited(obj_cap) and stats["objects_scanned"] > obj_cap:
                        stats["truncated"] = True
                        break
                    key = obj.get("Key", "")
                    if not key.endswith(".log.gz"):
                        continue
                    stats["objects_read"] += 1
                    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                    for rec in _iter_plaintext_records(body, region, scope_tags):
                        if not records_unlimited(max_records) and _written_count(writer, records) >= max_records:
                            stats["truncated"] = True
                            break
                        if not _in_window(rec, start, end):
                            continue
                        rec["_ventra_log_key"] = key
                        rec["_ventra_s3_bucket"] = bucket
                        rec["_ventra_collect_source"] = "s3_logs"
                        if writer is not None:
                            writer.write_record(rec)
                        else:
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

    if stats["truncated"] and not records_unlimited(max_records):
        gaps.append(
            (
                "vpc_flow_s3",
                GapReason.COLLECTOR_ERROR,
                f"{bucket}: truncated at {obj_cap} objects / {max_records} records; "
                "narrow the window or use enterprise profile.",
            )
        )

    if log and stats["records"]:
        log(f"S3 {bucket}: {stats['records']} flow records ({stats['objects_read']} objects)")
    return records, stats
