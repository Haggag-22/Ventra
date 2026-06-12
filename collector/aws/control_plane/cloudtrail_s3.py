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
from typing import Any

from ...lib.models import GapReason
from ..client_factory import AccessDenied

# Keep CloudShell runs bounded.
MAX_LOG_OBJECTS = 2000
MAX_CATEGORY_RECORDS = 200_000

DATA_CATEGORIES = frozenset({"Data"})
NETWORK_CATEGORIES = frozenset({"NetworkActivity"})
INSIGHT_CATEGORIES = frozenset({"Insight"})

# CloudTrail delivers each event category to its own folder under AWSLogs/<account>/
# (see "Finding your CloudTrail log files" in the CloudTrail user guide):
#   management + data   -> CloudTrail/
#   insights            -> CloudTrail-Insight/
#   network activity    -> CloudTrail-NetworkActivity/
CATEGORY_SUBFOLDERS: dict[frozenset[str], str] = {
    DATA_CATEGORIES: "CloudTrail",
    INSIGHT_CATEGORIES: "CloudTrail-Insight",
    NETWORK_CATEGORIES: "CloudTrail-NetworkActivity",
}
# The shared folder also contains management events, so records scanned there must be
# strictly category-filtered; dedicated folders contain only their own category.
SHARED_SUBFOLDER = "CloudTrail"


def trail_s3_prefix(trail: dict[str, Any]) -> str | None:
    if not trail.get("S3BucketName"):
        return None
    prefix = (trail.get("S3KeyPrefix") or "").strip()
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix or "AWSLogs/"


def trail_log_base(trail: dict[str, Any]) -> str | None:
    """The key prefix under which AWSLogs/ lives.

    CloudTrail always delivers to ``<custom prefix>/AWSLogs/...`` — a custom S3KeyPrefix is
    *prepended* to AWSLogs/, it does not replace it.
    """
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


def _day_prefixes(
    account_base: str, subfolder: str, region: str, start: datetime, end: datetime
) -> list[str]:
    """Daily key prefixes, e.g. ``AWSLogs/<acct>/CloudTrail/<region>/2026/06/11/``.

    ``account_base`` already ends with ``<account id>/`` (and includes the org id for
    organization trails)."""
    return [
        f"{account_base}{subfolder}/{region}/{d.year:04d}/{d.month:02d}/{d.day:02d}/"
        for d in _iter_days(start, end)
    ]


def _account_base(cf, trail: dict[str, Any], account_id: str, home: str) -> str | None:
    """Resolve the per-account key base, handling organization trails.

    Organization trails deliver to ``AWSLogs/<org id>/<account id>/...``. The trail config
    does not carry the org id, so discover it by listing the AWSLogs/ folder for an ``o-*``
    common prefix; fall back to the plain layout when nothing is found or listing is denied.
    """
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
        except Exception:  # noqa: BLE001 - fall back to non-org layout
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
    subfolder = CATEGORY_SUBFOLDERS.get(categories, SHARED_SUBFOLDER)
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

    try:
        for region in trail_regions:
            for prefix in _day_prefixes(account_base, subfolder, region, start, end):
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
                            # The shared CloudTrail/ folder mixes management and data
                            # events, so filter strictly there. Dedicated folders only
                            # ever contain their own category — keep records even when
                            # eventCategory is absent from the payload.
                            if cat:
                                if cat not in categories:
                                    continue
                            elif subfolder == SHARED_SUBFOLDER:
                                continue
                            ts = _parse_event_time(rec.get("eventTime", ""))
                            if not _in_window(ts, start, end):
                                continue
                            out = dict(rec)
                            out["_ventra_region"] = out.get("awsRegion") or region
                            out["_ventra_log_key"] = key
                            out["_ventra_s3_bucket"] = bucket
                            out["_ventra_collect_source"] = "s3_logs"
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
