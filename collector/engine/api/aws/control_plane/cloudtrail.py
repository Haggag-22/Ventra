"""CloudTrail collector — the control-plane backbone of cloud IR.

Captures:
  1. **Trail configuration** — trails, selectors (management / data / network / insights),
     log validation, and S3 delivery settings.
  2. **Management events** — from the trail's S3 log files (the authoritative copy that
     validate-logs covers and that reaches past the API's ~90-day window). Falls back to
     LookupEvents only when no trail delivers management logs to readable S3.
  3. **Insight events** — from S3 log files (and LookupEvents in the fallback path).
  4. **Data events** — from the trail's S3 log files when data events are enabled.
  5. **Network activity events** — from the trail's S3 log files when enabled.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from .cloudtrail_s3 import (
    DATA_CATEGORIES,
    INSIGHT_CATEGORIES,
    MANAGEMENT_CATEGORIES,
    NETWORK_CATEGORIES,
    collect_s3_trail_records,
    coverage_summary,
    data_events_configured,
    insight_events_configured,
    lookup_event_category,
    management_events_configured,
    merge_dedupe,
    network_activity_configured,
    trail_is_logging_to_s3,
)
from .cloudtrail_validation import TrailValidationResult, validate_trail_logs, validation_gaps

# Bound the in-memory LookupEvents pull so a busy account can't exhaust a CloudShell.
MAX_LOOKUP_RECORDS = 200_000


class CloudTrailCollector(Collector):
    name = "cloudtrail"
    priority = 1
    description = (
        "CloudTrail trail config; management, insight, data and network-activity events "
        "from the trail's S3 logs (LookupEvents fallback for management when no trail "
        "delivers to S3), plus S3 log integrity validation (validate-logs)."
    )
    required_actions = (
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetInsightSelectors",
        "cloudtrail:LookupEvents",
        "s3:ListBucket",
        "s3:GetObject",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []

        config = self._trail_config(cf, gaps)
        config["event_coverage"] = coverage_summary(config.get("trails", []))

        window = self.ctx.time_window
        start = window.since or (datetime.now(UTC) - timedelta(days=90))
        end = window.until or datetime.now(UTC)

        validation_results = self._validate_trail_logs(config.get("trails", []), start, end)
        config["log_validation"] = {
            "window": window.to_manifest(),
            "trails": [r.to_dict() for r in validation_results],
            "any_invalid": any(r.status == "invalid" for r in validation_results),
            "any_validated": any(r.status == "valid" for r in validation_results),
        }
        gaps.extend(validation_gaps(validation_results))

        s3_by_bucket: dict[str, dict[str, Any]] = {}

        # Discover trails, then collect their logs straight from the delivery buckets — the
        # authoritative copy that validate-logs covers and that reaches past the API's ~90-day
        # window. CloudTrail Event History (LookupEvents) is only a backup, used when no trail
        # delivers management logs to S3 or every trail bucket read fails.
        mgmt_records, lookup_insight_records, mgmt_collection = self._collect_management_events(
            cf, config, gaps, start, end, s3_by_bucket
        )
        config["management_collection"] = mgmt_collection
        mgmt_source = "s3_logs" if mgmt_collection["mode"] == "trails" else "lookup_events"

        insight_s3_records, insight_stats = self._collect_s3_category(
            cf,
            config,
            gaps,
            start,
            end,
            INSIGHT_CATEGORIES,
            insight_events_configured,
            "insight_events",
            require_s3=False,
            s3_by_bucket=s3_by_bucket,
        )
        insight_records = merge_dedupe(lookup_insight_records, insight_s3_records)

        data_records, data_stats = self._collect_s3_category(
            cf,
            config,
            gaps,
            start,
            end,
            DATA_CATEGORIES,
            data_events_configured,
            "data_events",
            s3_by_bucket=s3_by_bucket,
        )
        network_records, network_stats = self._collect_s3_category(
            cf,
            config,
            gaps,
            start,
            end,
            NETWORK_CATEGORIES,
            network_activity_configured,
            "network_activity",
            s3_by_bucket=s3_by_bucket,
        )

        if config["event_coverage"]["insight_events_configured"] and not insight_records:
            gaps.append(
                (
                    "insight_events",
                    GapReason.NOT_PRESENT,
                    "Insights enabled but no insight events in window.",
                )
            )

        config["s3_collection"] = {
            "management_events": {
                "configured": mgmt_collection["trails_total"] > 0,
                "mode": mgmt_collection["mode"],
                "records": mgmt_collection["records"],
                "trails_total": mgmt_collection["trails_total"],
                "trails_collected": mgmt_collection["trails_collected"],
            },
            "insight_events": insight_stats,
            "data_events": data_stats,
            "network_activity": network_stats,
            "by_bucket": list(s3_by_bucket.values()),
        }
        config["collection_summary"] = self._build_collection_summary(
            config.get("trails", []),
            mgmt_records,
            mgmt_source,
            lookup_insight_records,
            insight_s3_records,
            data_records,
            network_records,
            s3_by_bucket,
        )

        files = []
        total = 0

        if mgmt_records:
            files.append(self.write_jsonl(mgmt_records, "events.jsonl.gz"))
            total += len(mgmt_records)
        if insight_records:
            files.append(self.write_jsonl(insight_records, "events_insights.jsonl.gz"))
            total += len(insight_records)
        if data_records:
            files.append(self.write_jsonl(data_records, "events_data.jsonl.gz"))
            total += len(data_records)
        if network_records:
            files.append(self.write_jsonl(network_records, "events_network.jsonl.gz"))
            total += len(network_records)

        files.append(self.write_json(config, "config.json"))

        if total:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif gaps:
            status = SourceStatus.PARTIAL
        else:
            status = SourceStatus.EMPTY
            gaps.append(
                ("cloudtrail", GapReason.NOT_PRESENT, "No CloudTrail events in window.")
            )

        self.write_meta(
            {
                "source": self.name,
                "records": total,
                "management_events": len(mgmt_records),
                "management_source": mgmt_source,
                "management_collection": mgmt_collection,
                "insight_events": len(insight_records),
                "data_events": len(data_records),
                "network_activity_events": len(network_records),
                "lookup_insight_events": len(lookup_insight_records),
                "regions": self.ctx.regions,
                "window": window.to_manifest(),
                "trails": len(config.get("trails", [])),
                "log_validation_enabled": config.get("any_log_validation_enabled"),
                "event_coverage": config["event_coverage"],
                "s3_collection": config["s3_collection"],
                "log_validation": config["log_validation"],
                "collection_summary": config["collection_summary"],
            }
        )

        notes = (
            f"{len(mgmt_records)} management ({mgmt_source}), {len(insight_records)} insight, "
            f"{len(data_records)} data, {len(network_records)} network-activity; "
            f"{len(config.get('trails', []))} trail(s)."
        )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=total,
            gaps=gaps,
            notes=notes,
        )

    def _collect_lookup_events(
        self,
        cf,
        gaps: list[tuple[str, GapReason, str]],
        start: datetime,
        end: datetime,
    ) -> tuple[list[dict], list[dict]]:
        management: list[dict] = []
        insights: list[dict] = []
        truncated = False
        for region in self.ctx.regions:
            if truncated:
                break
            try:
                for ev in cf.paginate(
                    "cloudtrail",
                    region,
                    "lookup_events",
                    "Events",
                    StartTime=start,
                    EndTime=end,
                ):
                    if len(management) + len(insights) >= MAX_LOOKUP_RECORDS:
                        truncated = True
                        break
                    ev["_ventra_region"] = region
                    ev["_ventra_collect_source"] = "lookup_events"
                    if lookup_event_category(ev) == "Insight":
                        insights.append(ev)
                    else:
                        management.append(ev)
            except AccessDenied as exc:
                gaps.append(("cloudtrail", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except ServiceNotEnabled:
                continue
        if truncated:
            gaps.append(
                (
                    "cloudtrail",
                    GapReason.COLLECTOR_ERROR,
                    f"LookupEvents truncated at {MAX_LOOKUP_RECORDS} records; "
                    "narrow the window (--since/--until) for full coverage.",
                )
            )
        return management, insights

    def _collect_management_events(
        self,
        cf,
        config: dict,
        gaps: list[tuple[str, GapReason, str]],
        start: datetime,
        end: datetime,
        s3_by_bucket: dict[str, dict[str, Any]],
    ) -> tuple[list[dict], list[dict], dict[str, Any]]:
        """Collect management events from trail S3 logs, backing off to Event History.

        Returns ``(management_records, lookup_insight_records, collection)``. ``collection.mode``
        is ``"trails"`` when at least one trail's S3 logs were read, else ``"event_history"``.
        ``lookup_insight_records`` is populated only on the Event-History path — insights are
        otherwise read from S3 like every other category.
        """
        trails = config.get("trails", [])
        s3_trails = [
            t for t in trails if management_events_configured(t) and trail_is_logging_to_s3(t)
        ]
        collection: dict[str, Any] = {
            "mode": "event_history",
            "trails": [],
            "trails_total": len(s3_trails),
            "trails_collected": 0,
            "buckets": [],
            "records": 0,
            "fallback_reason": "",
        }

        # No trail delivers management logs to S3 — Event History is the only source.
        if not s3_trails:
            collection["fallback_reason"] = "no_s3_trail"
            self._log("No trail delivers logs to S3 — collecting from CloudTrail Event History.")
            mgmt, lookup_insight = self._collect_lookup_events(cf, gaps, start, end)
            collection["records"] = len(mgmt)
            return mgmt, lookup_insight, collection

        account_id = self.ctx.account_id
        records: list[dict] = []
        buckets: list[str] = []
        any_success = False
        any_denied = False

        for trail in s3_trails:
            self._log(f"Collecting trail logs for {trail.get('Name', '')}…")
            trail_gaps: list[tuple[str, GapReason, str]] = []
            recs, stats = collect_s3_trail_records(
                cf,
                trail,
                account_id,
                self.ctx.regions,
                start,
                end,
                MANAGEMENT_CATEGORIES,
                trail_gaps,
                log=lambda msg: self._log(msg),
            )
            gaps.extend(trail_gaps)
            denied = any(reason == GapReason.ACCESS_DENIED for _, reason, _ in trail_gaps)
            objects_read = int(stats.get("objects_read") or 0)
            bucket = stats.get("bucket") or trail.get("S3BucketName") or ""

            if objects_read > 0 or recs:
                status, reason = "collected", ""
                any_success = True
                records.extend(recs)
                self._merge_s3_bucket_stats(
                    s3_by_bucket, trail, "management_events", len(recs), stats
                )
                if bucket and bucket not in buckets:
                    buckets.append(bucket)
            elif denied:
                status, reason = "denied", "access_denied"
                any_denied = True
            else:
                status, reason = "empty", "no_logs_in_window"

            collection["trails"].append(
                {
                    "trail_name": trail.get("Name", ""),
                    "trail_arn": trail.get("TrailARN", ""),
                    "bucket": bucket,
                    "status": status,
                    "records": len(recs),
                    "objects_read": objects_read,
                    "reason": reason,
                }
            )

        if any_success:
            collection["mode"] = "trails"
            collection["trails_collected"] = sum(
                1 for t in collection["trails"] if t["status"] == "collected"
            )
            collection["buckets"] = buckets
            collection["records"] = len(records)
            self._log(
                f"Collected logs from {collection['trails_collected']}/{len(s3_trails)} trail(s) "
                f"across {len(buckets)} bucket(s)."
            )
            return records, [], collection

        # Every trail bucket read failed — back off to CloudTrail Event History.
        collection["fallback_reason"] = "access_denied" if any_denied else "no_logs"
        gaps.append(
            (
                "management_events",
                GapReason.ACCESS_DENIED if any_denied else GapReason.NOT_PRESENT,
                "Trail S3 log collection produced no management events for any trail; "
                "fell back to CloudTrail Event History (LookupEvents).",
            )
        )
        self._log("Trail log collection failed for all trails — using CloudTrail Event History.")
        mgmt, lookup_insight = self._collect_lookup_events(cf, gaps, start, end)
        collection["records"] = len(mgmt)
        return mgmt, lookup_insight, collection

    def _validate_trail_logs(
        self,
        trails: list[dict[str, Any]],
        start: datetime,
        end: datetime,
    ) -> list[TrailValidationResult]:
        """Validate S3 log integrity for trails with log file validation enabled."""
        results: list[TrailValidationResult] = []
        account_id = self.ctx.account_id
        for trail in trails:
            if not trail.get("LogFileValidationEnabled"):
                continue
            self._log(f"Validating log integrity for trail {trail.get('Name', '')}…")
            res = validate_trail_logs(trail, account_id, start, end)
            results.append(res)
            if res.status == "valid":
                self._log(
                    f"  {res.trail_name}: {res.digest_valid}/{res.digest_total} digests, "
                    f"{res.log_valid}/{res.log_total} log files valid"
                )
            elif res.status == "invalid":
                self._log(
                    f"  {res.trail_name}: INTEGRITY FAILURE — "
                    f"{res.digest_invalid} invalid digest(s), {res.log_invalid} invalid log(s)"
                )
            elif res.status == "error":
                self._log(f"  {res.trail_name}: validation error ({res.skip_reason})")
        return results

    def _collect_s3_category(
        self,
        cf,
        config: dict,
        gaps: list[tuple[str, GapReason, str]],
        start: datetime,
        end: datetime,
        categories: frozenset[str],
        configured_fn,
        gap_name: str,
        *,
        require_s3: bool = True,
        s3_by_bucket: dict[str, dict[str, Any]] | None = None,
    ) -> tuple[list[dict], dict]:
        trails = config.get("trails", [])
        if not any(configured_fn(t) for t in trails):
            return [], {"configured": False, "records": 0}

        if not any(trail_is_logging_to_s3(t) for t in trails):
            if require_s3:
                gaps.append(
                    (
                        gap_name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "Event type enabled but trail does not deliver logs to S3.",
                    )
                )
            return [], {"configured": True, "records": 0, "s3_logging": False}

        combined: list[dict] = []
        combined_stats: dict = {"configured": True, "records": 0, "s3_logging": True}
        account_id = self.ctx.account_id

        for trail in trails:
            if not configured_fn(trail) or not trail_is_logging_to_s3(trail):
                continue
            recs, stats = collect_s3_trail_records(
                cf,
                trail,
                account_id,
                self.ctx.regions,
                start,
                end,
                categories,
                gaps,
                log=lambda msg: self._log(msg),
            )
            combined.extend(recs)
            self._merge_s3_bucket_stats(s3_by_bucket, trail, gap_name, len(recs), stats)
            for key in ("objects_scanned", "objects_read", "records", "truncated"):
                if key == "truncated":
                    combined_stats["truncated"] = combined_stats.get("truncated") or stats.get(
                        "truncated"
                    )
                else:
                    combined_stats[key] = combined_stats.get(key, 0) + stats.get(key, 0)

        combined_stats["records"] = len(combined)
        if require_s3 and combined_stats.get("configured") and not combined:
            gaps.append(
                (
                    gap_name,
                    GapReason.NOT_PRESENT,
                    f"No {gap_name.replace('_', ' ')} log records in window (check S3 path/permissions).",
                )
            )
        return combined, combined_stats

    @staticmethod
    def _merge_s3_bucket_stats(
        s3_by_bucket: dict[str, dict[str, Any]] | None,
        trail: dict[str, Any],
        gap_name: str,
        record_count: int,
        stats: dict[str, Any],
    ) -> None:
        if s3_by_bucket is None or record_count <= 0:
            return
        bucket = stats.get("bucket") or trail.get("S3BucketName")
        if not bucket:
            return
        entry = s3_by_bucket.setdefault(
            bucket,
            {
                "bucket": bucket,
                "trail_arns": [],
                "events": {
                    "management": 0,
                    "data": 0,
                    "insight": 0,
                    "network_activity": 0,
                    "total": 0,
                },
                "objects_read": 0,
                "truncated": False,
            },
        )
        arn = str(trail.get("TrailARN") or "")
        if arn and arn not in entry["trail_arns"]:
            entry["trail_arns"].append(arn)
        category_key = {
            "management_events": "management",
            "data_events": "data",
            "insight_events": "insight",
            "network_activity": "network_activity",
        }.get(gap_name, gap_name)
        entry["events"][category_key] = entry["events"].get(category_key, 0) + record_count
        entry["events"]["total"] += record_count
        entry["objects_read"] += int(stats.get("objects_read") or 0)
        entry["truncated"] = entry["truncated"] or bool(stats.get("truncated"))

    @staticmethod
    def _trail_summary(trail: dict[str, Any]) -> dict[str, Any]:
        status = trail.get("Status") or {}
        return {
            "name": trail.get("Name", ""),
            "arn": trail.get("TrailARN", ""),
            "home_region": trail.get("HomeRegion", ""),
            "s3_bucket": trail.get("S3BucketName", ""),
            "s3_key_prefix": trail.get("S3KeyPrefix", ""),
            "is_logging": bool(status.get("IsLogging")),
            "is_multi_region": bool(trail.get("IsMultiRegionTrail")),
            "is_organization": bool(trail.get("IsOrganizationTrail")),
            "log_file_validation": bool(trail.get("LogFileValidationEnabled")),
            "management_events_configured": management_events_configured(trail),
            "data_events_configured": data_events_configured(trail),
            "network_activity_configured": network_activity_configured(trail),
            "insight_events_configured": insight_events_configured(trail),
        }

    def _build_collection_summary(
        self,
        trails: list[dict[str, Any]],
        mgmt_records: list[dict],
        mgmt_source: str,
        lookup_insight_records: list[dict],
        insight_s3_records: list[dict],
        data_records: list[dict],
        network_records: list[dict],
        s3_by_bucket: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        mgmt_from_s3 = mgmt_source == "s3_logs"
        lookup_management = 0 if mgmt_from_s3 else len(mgmt_records)
        s3_management = len(mgmt_records) if mgmt_from_s3 else 0
        lookup_total = lookup_management + len(lookup_insight_records)
        s3_total = (
            s3_management + len(insight_s3_records) + len(data_records) + len(network_records)
        )
        return {
            "trail_count": len(trails),
            "trails": [self._trail_summary(t) for t in trails],
            "management_source": mgmt_source,
            "events": {
                "lookup_api": {
                    "management": lookup_management,
                    "insight": len(lookup_insight_records),
                    "total": lookup_total,
                },
                "s3": {
                    "total": s3_total,
                    "management": s3_management,
                    "data": len(data_records),
                    "insight": len(insight_s3_records),
                    "network_activity": len(network_records),
                    "by_bucket": list(s3_by_bucket.values()),
                },
            },
        }

    def _trail_config(self, cf, gaps) -> dict:
        trails: list[dict] = []
        any_validation = False
        seen = set()
        for region in self.ctx.regions:
            try:
                described = cf.call("cloudtrail", region, "describe_trails").get("trailList", [])
            except AccessDenied as exc:
                gaps.append(
                    ("cloudtrail_config", GapReason.ACCESS_DENIED, f"{region}: {exc.message}")
                )
                continue
            except ServiceNotEnabled:
                continue
            for trail in described:
                arn = trail.get("TrailARN", "")
                if arn in seen:
                    continue
                seen.add(arn)
                trail = dict(trail)
                if trail.get("LogFileValidationEnabled"):
                    any_validation = True
                home = trail.get("HomeRegion", region)
                try:
                    trail["Status"] = cf.call(
                        "cloudtrail", home, "get_trail_status", Name=arn
                    )
                    trail["EventSelectors"] = cf.call(
                        "cloudtrail", home, "get_event_selectors", TrailName=arn
                    )
                except AccessDenied as exc:
                    # Without status, S3 log collection for this trail is skipped — that
                    # is a gap worth surfacing, not hiding.
                    gaps.append(
                        ("cloudtrail_config", GapReason.ACCESS_DENIED, f"{arn}: {exc.message}")
                    )
                except Exception:  # noqa: BLE001 - keep the trail entry, just less enriched
                    pass
                try:
                    trail["InsightSelectors"] = cf.call(
                        "cloudtrail", home, "get_insight_selectors", TrailName=arn
                    )
                except Exception:  # InsightNotEnabledException et al. — Insights are off
                    trail["InsightSelectors"] = None
                trails.append(trail)

        return {
            "trails": trails,
            "trail_count": len(trails),
            "any_log_validation_enabled": any_validation,
            "multi_region_trail_present": any(t.get("IsMultiRegionTrail") for t in trails),
            "organization_trail_present": any(t.get("IsOrganizationTrail") for t in trails),
        }
