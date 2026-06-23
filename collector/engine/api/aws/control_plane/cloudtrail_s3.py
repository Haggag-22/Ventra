"""Read CloudTrail log files from the trail's S3 bucket.

LookupEvents returns management and insight events. Data events, network activity events,
and insight events may also appear in S3 log files; Ventra reads those from S3 when the trail
is configured to log there.
"""

from __future__ import annotations

import gzip
import io
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from collector.lib.limits import (
    DEFAULT_MAX_LOG_OBJECTS,
    DEFAULT_MAX_RECORDS,
    records_unlimited,
    resolve_max_objects,
)
from collector.lib.models import GapReason
from collector.clouds.aws.client_factory import AccessDenied

if TYPE_CHECKING:
    from collector.lib.base import JsonlWriter

MAX_LOG_OBJECTS = DEFAULT_MAX_LOG_OBJECTS
MAX_CATEGORY_RECORDS = DEFAULT_MAX_RECORDS

DATA_CATEGORIES = frozenset({"Data"})
NETWORK_CATEGORIES = frozenset({"NetworkActivity"})
INSIGHT_CATEGORIES = frozenset({"Insight"})
MANAGEMENT_CATEGORIES = frozenset({"Management"})

CATEGORY_SUBFOLDERS: dict[frozenset[str], str] = {
    MANAGEMENT_CATEGORIES: "CloudTrail",
    DATA_CATEGORIES: "CloudTrail",
    INSIGHT_CATEGORIES: "CloudTrail-Insight",
    NETWORK_CATEGORIES: "CloudTrail-NetworkActivity",
}
SHARED_SUBFOLDER = "CloudTrail"


def trail_s3_prefix(trail: dict[str, Any]) -> str | None:
    if not trail.get("S3BucketName"):
        return None
    prefix = (trail.get("S3KeyPrefix") or "").strip()
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix or "AWSLogs/"


def trail_log_base(trail: dict[str, Any]) -> str | None:
    prefix = trail_s3_prefix(trail)
    if prefix is None:
        return None
    if prefix == "AWSLogs/" or prefix.endswith("/AWSLogs/"):
        return prefix
    return prefix + "AWSLogs/"


def trail_is_logging_to_s3(trail: dict[str, Any]) -> bool:
    if not trail.get("S3BucketName"):
        return False
    status = trail.get("Status") or {}
    return bool(status.get("IsLogging"))


def data_events_configured(trail: dict[str, Any]) -> bool:
    es = trail.get("EventSelectors") or {}
    for sel in es.get("EventSelectors") or []:
        if sel.get("DataResources"):
            return True
    for adv in es.get("AdvancedEventSelectors") or []:
        for fs in adv.get("FieldSelectors") or []:
            if fs.get("Field") == "eventCategory" and "Data" in (fs.get("Equals") or []):
                return True
    return False


def network_activity_configured(trail: dict[str, Any]) -> bool:
    es = trail.get("EventSelectors") or {}
    for adv in es.get("AdvancedEventSelectors") or []:
        for fs in adv.get("FieldSelectors") or []:
            if fs.get("Field") == "eventCategory" and "NetworkActivity" in (fs.get("Equals") or []):
                return True
    return False


def management_events_configured(trail: dict[str, Any]) -> bool:
    es = trail.get("EventSelectors") or {}
    classic = es.get("EventSelectors")
    advanced = es.get("AdvancedEventSelectors")
    if classic:
        return any(sel.get("IncludeManagementEvents", True) for sel in classic)
    if advanced:
        for adv in advanced:
            for fs in adv.get("FieldSelectors") or []:
                if fs.get("Field") == "eventCategory" and "Management" in (fs.get("Equals") or []):
                    return True
        return False
    return True


def insight_events_configured(trail: dict[str, Any]) -> bool:
    raw = trail.get("InsightSelectors")
    if not raw:
        return False
    selectors = raw.get("InsightSelectors") if isinstance(raw, dict) else raw
    return bool(selectors)


def lookup_event_category(ev: dict[str, Any]) -> str:
    inner = ev.get("CloudTrailEvent")
    if isinstance(inner, str):
        try:
            detail = json.loads(inner)
            return detail.get("eventCategory") or "Management"
        except json.JSONDecodeError:
            pass
    return ev.get("eventCategory") or "Management"


def event_id(rec: dict[str, Any]) -> str:
    if rec.get("EventId"):
        return str(rec["EventId"])
    inner = rec.get("CloudTrailEvent")
    if isinstance(inner, str):
        try:
            return str(json.loads(inner).get("eventID") or "")
        except json.JSONDecodeError:
            pass
    return str(rec.get("eventID") or "")


def merge_dedupe(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for group in groups:
        for rec in group:
            eid = event_id(rec)
            if eid:
                if eid in seen:
                    continue
                seen.add(eid)
            out.append(rec)
    return out


def coverage_summary(trails: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "data_events_configured": any(data_events_configured(t) for t in trails),
        "network_activity_configured": any(network_activity_configured(t) for t in trails),
        "insight_events_configured": any(insight_events_configured(t) for t in trails),
        "s3_logging_trails": sum(1 for t in trails if trail_is_logging_to_s3(t)),
    }


def _iter_days(start: datetime, end: datetime):
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    last = end.replace(hour=0, minute=0, second=0, microsecond=0)
    while day <= last:
        yield day
        day += timedelta(days=1)


def _day_prefixes(
    account_base: str, subfolder: str, region: str, start: datetime, end: datetime
) -> list[str]:
    return [
        f"{account_base}{subfolder}/{region}/{d.year:04d}/{d.month:02d}/{d.day:02d}/"
        for d in _iter_days(start, end)
    ]


def _account_base(cf, trail: dict[str, Any], account_id: str, home: str) -> str | None:
    base = trail_log_base(trail)
    bucket = trail.get("S3BucketName")
    if not base or not bucket:
        return None
    if trail.get("IsOrganizationTrail"):
        try:
            resp = cf.call(
                "s3", home, "list_objects_v2", Bucket=bucket, Prefix=base, Delimiter="/"
            )
            for cp in resp.get("CommonPrefixes") or []:
                folder = cp.get("Prefix", "")[len(base):].strip("/")
                if folder.startswith("o-"):
                    return f"{base}{folder}/{account_id}/"
        except Exception:  # noqa: BLE001
            pass
    return f"{base}{account_id}/"


def _parse_event_time(val: str) -> datetime | None:
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _in_window(ts: datetime | None, start: datetime, end: datetime) -> bool:
    return ts is not None and start <= ts <= end


def _written_count(writer: JsonlWriter | None, records: list[dict[str, Any]]) -> int:
    return writer.count if writer is not None else len(records)


def collect_s3_trail_records(
    cf,
    trail: dict[str, Any],
    account_id: str,
    regions: list[str],
    start: datetime,
    end: datetime,
    categories: frozenset[str],
    gaps: list[tuple[str, GapReason, str]],
    *,
    log: Callable[[str], None] | None = None,
    max_records: int = MAX_CATEGORY_RECORDS,
    max_objects: int | None = None,
    writer: JsonlWriter | None = None,
    seen_event_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull records for ``categories`` from the trail's S3 log files in the time window."""
    subfolder = CATEGORY_SUBFOLDERS.get(categories, SHARED_SUBFOLDER)
    obj_cap = resolve_max_objects(max_records, max_objects)
    stats: dict[str, Any] = {
        "objects_scanned": 0,
        "objects_read": 0,
        "records": 0,
        "bucket": trail.get("S3BucketName"),
        "subfolder": subfolder,
        "truncated": False,
    }
    records: list[dict[str, Any]] = []
    bucket = trail.get("S3BucketName")
    home = trail.get("HomeRegion") or regions[0]
    account_base = _account_base(cf, trail, account_id, home)
    if not bucket or not account_base:
        return records, stats

    s3 = cf.client("s3", home)
    trail_regions = regions if trail.get("IsMultiRegionTrail") else [home]
    seen = seen_event_ids if seen_event_ids is not None else set()

    try:
        for region in trail_regions:
            for prefix in _day_prefixes(account_base, subfolder, region, start, end):
                if stats["truncated"]:
                    break
                try:
                    for obj in cf.paginate(
                        "s3",
                        home,
                        "list_objects_v2",
                        "Contents",
                        Bucket=bucket,
                        Prefix=prefix,
                    ):
                        stats["objects_scanned"] += 1
                        if stats["objects_scanned"] > obj_cap:
                            stats["truncated"] = True
                            break
                        key = obj.get("Key", "")
                        if not key.endswith(".json.gz"):
                            continue
                        stats["objects_read"] += 1
                        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
                            payload = json.loads(gz.read().decode("utf-8"))
                        for rec in payload.get("Records") or []:
                            if not records_unlimited(max_records) and _written_count(writer, records) >= max_records:
                                stats["truncated"] = True
                                break
                            cat = rec.get("eventCategory") or ""
                            if cat:
                                if cat not in categories:
                                    continue
                            elif subfolder == SHARED_SUBFOLDER:
                                continue
                            ts = _parse_event_time(rec.get("eventTime", ""))
                            if not _in_window(ts, start, end):
                                continue
                            out = dict(rec)
                            eid = event_id(out)
                            if eid and eid in seen:
                                continue
                            if eid:
                                seen.add(eid)
                            out["_ventra_region"] = out.get("awsRegion") or region
                            out["_ventra_log_key"] = key
                            out["_ventra_s3_bucket"] = bucket
                            out["_ventra_collect_source"] = "s3_logs"
                            if writer is not None:
                                writer.write_record(out)
                            else:
                                records.append(out)
                            stats["records"] += 1
                        if stats["truncated"]:
                            break
                except AccessDenied as exc:
                    gaps.append(
                        (
                            "cloudtrail_s3",
                            GapReason.ACCESS_DENIED,
                            f"{bucket}/{prefix}: {exc.message}",
                        )
                    )
                if stats["truncated"]:
                    break
            if stats["truncated"]:
                break
    except AccessDenied as exc:
        gaps.append(
            ("cloudtrail_s3", GapReason.ACCESS_DENIED, f"{bucket}: {exc.message}")
        )

    if stats["truncated"] and not records_unlimited(max_records):
        gaps.append(
            (
                "cloudtrail_s3",
                GapReason.COLLECTOR_ERROR,
                f"{bucket}: truncated at {obj_cap} objects / {max_records} records; "
                "narrow the window (--since/--until) or use enterprise profile.",
            )
        )

    if log and stats["records"]:
        log(f"S3 {bucket}: {stats['records']} {','.join(sorted(categories))} records")
    return records, stats
