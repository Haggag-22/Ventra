"""Read CloudTrail log files from the trail's S3 bucket.

LookupEvents returns management and insight events. Data events, network activity events,
and insight events may also appear in S3 log files; Harbor reads those from S3 when the trail
is configured to log there.
"""

from __future__ import annotations

import gzip
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from ...common.models import GapReason
from ..client_factory import AccessDenied

# Keep CloudShell runs bounded.
MAX_LOG_OBJECTS = 2000
MAX_CATEGORY_RECORDS = 200_000

DATA_CATEGORIES = frozenset({"Data"})
NETWORK_CATEGORIES = frozenset({"NetworkActivity"})
INSIGHT_CATEGORIES = frozenset({"Insight"})


def trail_s3_prefix(trail: dict[str, Any]) -> str | None:
    if not trail.get("S3BucketName"):
        return None
    prefix = (trail.get("S3KeyPrefix") or "").strip()
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix or "AWSLogs/"


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


def insight_events_configured(trail: dict[str, Any]) -> bool:
    raw = trail.get("InsightSelectors")
    if not raw:
        return False
    selectors = raw.get("InsightSelectors") if isinstance(raw, dict) else raw
    return bool(selectors)


def lookup_event_category(ev: dict[str, Any]) -> str:
    """Return CloudTrail eventCategory from a LookupEvents record."""
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
    """Summarize which optional event categories are configured on any trail."""
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


def _day_prefixes(s3_prefix: str, account_id: str, region: str, start: datetime, end: datetime) -> list[str]:
    return [
        f"{s3_prefix}{account_id}/CloudTrail/{region}/{d.year:04d}/{d.month:02d}/{d.day:02d}/"
        for d in _iter_days(start, end)
    ]


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
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull records for ``categories`` from the trail's S3 log files in the time window."""
    stats: dict[str, Any] = {
        "objects_scanned": 0,
        "objects_read": 0,
        "records": 0,
        "bucket": trail.get("S3BucketName"),
        "truncated": False,
    }
    records: list[dict[str, Any]] = []
    bucket = trail.get("S3BucketName")
    s3_prefix = trail_s3_prefix(trail)
    if not bucket or not s3_prefix:
        return records, stats

    home = trail.get("HomeRegion") or regions[0]
    s3 = cf.client("s3", home)
    trail_regions = regions if trail.get("IsMultiRegionTrail") else [home]

    try:
        for region in trail_regions:
            for prefix in _day_prefixes(s3_prefix, account_id, region, start, end):
                if stats["objects_scanned"] >= MAX_LOG_OBJECTS:
                    stats["truncated"] = True
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
                        if stats["objects_scanned"] > MAX_LOG_OBJECTS:
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
                            if len(records) >= MAX_CATEGORY_RECORDS:
                                stats["truncated"] = True
                                break
                            cat = rec.get("eventCategory") or ""
                            if cat not in categories:
                                continue
                            ts = _parse_event_time(rec.get("eventTime", ""))
                            if not _in_window(ts, start, end):
                                continue
                            out = dict(rec)
                            out["_harbor_region"] = out.get("awsRegion") or region
                            out["_harbor_log_key"] = key
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

    if log and stats["records"]:
        log(f"S3 {bucket}: {stats['records']} {','.join(sorted(categories))} records")
    return records, stats
