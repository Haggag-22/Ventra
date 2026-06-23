"""CloudTrail collector — the control-plane backbone of cloud IR.

Captures:
  1. **Trail configuration** — trails, selectors (management / data / network / insights),
     log validation, and S3 delivery settings.
  2. **Management events** — from the trail's S3 log files (the authoritative copy that
     validate-logs covers and that reaches past the API's ~90-day window). Falls back to
     LookupEvents (Event History) only when no trails are discovered in the account.
  3. **Insight events** — from S3 log files when trails exist (LookupEvents only when no trails).
  4. **Data events** — from the trail's S3 log files when data events are enabled.
  5. **Network activity events** — from the trail's S3 log files when enabled.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS, records_unlimited
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
    event_id,
    insight_events_configured,
    lookup_event_category,
    management_events_configured,
    network_activity_configured,
    trail_is_logging_to_s3,
)
from .cloudtrail_validation import TrailValidationResult, validate_trail_logs, validation_gaps

# Bound the in-memory LookupEvents pull so a busy account can't exhaust a CloudShell.
MAX_LOOKUP_RECORDS = DEFAULT_MAX_RECORDS


class CloudTrailCollector(Collector):
    name = "cloudtrail"
    priority = 1
    description = (
        "CloudTrail trail config; management, insight, data and network-activity events "
        "from the trail's S3 logs (LookupEvents only when no trails exist), plus "
        "S3 log integrity validation (validate-logs)."
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
        # window. CloudTrail Event History (LookupEvents) is used only when DescribeTrails
        # finds no trails; otherwise management events come from S3 exclusively.
        mgmt_records, lookup_insight_records, mgmt_collection = self._collect_management_events(
            cf, config, gaps, start, end, s3_by_bucket
        )
        config["management_collection"] = mgmt_collection
        mgmt_source = "s3_logs" if mgmt_collection["mode"] == "trails" else "lookup_events"
        mgmt_count = int(mgmt_collection.get("records") or 0)

        cap = self.max_records(MAX_LOOKUP_RECORDS)
        stream_files: list = list(mgmt_collection.get("lookup_files") or [])
        stream_files.extend(mgmt_collection.get("s3_files") or [])

        insight_seen = {event_id(r) for r in lookup_insight_records if event_id(r)}
        with self.open_jsonl("events_insights.jsonl.gz") as insight_w:
            for rec in lookup_insight_records:
                insight_w.write_record(rec)
            _, insight_stats = self._collect_s3_category(
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
                writer=insight_w,
                seen_event_ids=insight_seen,
                max_records=cap,
            )
            insight_count = insight_w.count
            if insight_w.count:
                stream_files.append(insight_w.finalize())

        with self.open_jsonl("events_data.jsonl.gz") as data_w:
            _, data_stats = self._collect_s3_category(
                cf,
                config,
                gaps,
                start,
                end,
                DATA_CATEGORIES,
                data_events_configured,
                "data_events",
                s3_by_bucket=s3_by_bucket,
                writer=data_w,
                max_records=cap,
            )
            data_count = data_w.count
            if data_w.count:
                stream_files.append(data_w.finalize())

        with self.open_jsonl("events_network.jsonl.gz") as network_w:
            _, network_stats = self._collect_s3_category(
                cf,
                config,
                gaps,
                start,
                end,
                NETWORK_CATEGORIES,
                network_activity_configured,
                "network_activity",
                s3_by_bucket=s3_by_bucket,
                writer=network_w,
                max_records=cap,
            )
            network_count = network_w.count
            if network_w.count:
                stream_files.append(network_w.finalize())

        if config["event_coverage"]["insight_events_configured"] and insight_count == 0:
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
            mgmt_count,
            mgmt_source,
            len(lookup_insight_records),
            max(0, insight_count - len(lookup_insight_records)),
            data_count,
            network_count,
            s3_by_bucket,
        )

        files = list(stream_files)
        total = mgmt_count + insight_count + data_count + network_count

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
                "management_events": mgmt_count,
                "management_source": mgmt_source,
                "management_collection": mgmt_collection,
                "insight_events": insight_count,
                "data_events": data_count,
                "network_activity_events": network_count,
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
            f"{mgmt_count} management ({mgmt_source}), {insight_count} insight, "
            f"{data_count} data, {network_count} network-activity; "
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
        *,
        mgmt_writer=None,
    ) -> tuple[list[dict], list[dict]]:
        """Pull management + insight events from LookupEvents (Event History).

        When ``mgmt_writer`` is set, management events stream to disk and the returned
        management list is empty.
        """
        management: list[dict] = []
        insights: list[dict] = []
        truncated = False
        cap = self.max_records(MAX_LOOKUP_RECORDS)
        written = 0
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
                    total = written + len(management) + len(insights)
                    if not records_unlimited(cap) and total >= cap:
                        truncated = True
                        break
                    ev["_ventra_region"] = region
                    ev["_ventra_collect_source"] = "lookup_events"
                    if lookup_event_category(ev) == "Insight":
                        insights.append(ev)
                    elif mgmt_writer is not None:
                        mgmt_writer.write_record(ev)
                        written += 1
                    else:
                        management.append(ev)
            except AccessDenied as exc:
                gaps.append(("cloudtrail", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except ServiceNotEnabled:
                continue
        if truncated:
            self.append_truncation_gap(
                gaps,
                "cloudtrail",
                cap,
                f"LookupEvents truncated at {cap:,} records; "
                "narrow the window (--since/--until) for full coverage.",
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
        """Collect management events from trail S3 logs.

        When ``DescribeTrails`` finds no trails, falls back to CloudTrail Event History
        (``LookupEvents``). When any trail exists, management events come from S3 only —
        Event History is not consulted even if S3 returns zero records.

        Returns ``(management_records, lookup_insight_records, collection)``.
        ``lookup_insight_records`` is populated only on the no-trails Event-History path.
        """
        trails = config.get("trails", [])
        collection: dict[str, Any] = {
            "mode": "trails",
            "trails": [],
            "trails_total": len(trails),
            "trails_collected": 0,
            "buckets": [],
            "records": 0,
            "fallback_reason": "",
        }

        if not trails:
            collection["mode"] = "event_history"
            collection["trails_total"] = 0
            collection["fallback_reason"] = "no_trails"
            self._log("No CloudTrail trails found — collecting from CloudTrail Event History.")
            with self.open_jsonl("events.jsonl.gz") as mgmt_w:
                mgmt, lookup_insight = self._collect_lookup_events(
                    cf, gaps, start, end, mgmt_writer=mgmt_w
                )
                collection["records"] = mgmt_w.count or len(mgmt)
                if mgmt_w.count:
                    collection["lookup_files"] = [mgmt_w.finalize()]
            return mgmt, lookup_insight, collection

        account_id = self.ctx.account_id
        cap = self.max_records(MAX_LOOKUP_RECORDS)
        buckets: list[str] = []
        s3_attempts = 0

        with self.open_jsonl("events.jsonl.gz") as mgmt_w:
            for trail in trails:
                trail_name = trail.get("Name", "")
                trail_arn = trail.get("TrailARN", "")
                bucket = trail.get("S3BucketName") or ""

                if not trail_is_logging_to_s3(trail):
                    collection["trails"].append(
                        {
                            "trail_name": trail_name,
                            "trail_arn": trail_arn,
                            "bucket": bucket,
                            "status": "skipped",
                            "records": 0,
                            "objects_read": 0,
                            "reason": "s3_logging_disabled",
                        }
                    )
                    continue

                s3_attempts += 1
                self._log(f"Collecting trail logs for {trail_name}…")
                trail_gaps: list[tuple[str, GapReason, str]] = []
                _, stats = collect_s3_trail_records(
                    cf,
                    trail,
                    account_id,
                    self.ctx.regions,
                    start,
                    end,
                    MANAGEMENT_CATEGORIES,
                    trail_gaps,
                    log=lambda msg: self._log(msg),
                    max_records=cap,
                    writer=mgmt_w,
                )
                gaps.extend(trail_gaps)
                denied = any(reason == GapReason.ACCESS_DENIED for _, reason, _ in trail_gaps)
                objects_read = int(stats.get("objects_read") or 0)
                rec_count = int(stats.get("records") or 0)
                bucket = stats.get("bucket") or bucket

                if rec_count:
                    status, reason = "collected", ""
                    self._merge_s3_bucket_stats(
                        s3_by_bucket, trail, "management_events", rec_count, stats
                    )
                    if bucket and bucket not in buckets:
                        buckets.append(bucket)
                elif objects_read > 0:
                    status, reason = "empty", "no_events_in_window"
                elif denied:
                    status, reason = "denied", "access_denied"
                else:
                    status, reason = "empty", "no_logs_in_window"

                collection["trails"].append(
                    {
                        "trail_name": trail_name,
                        "trail_arn": trail_arn,
                        "bucket": bucket,
                        "status": status,
                        "records": rec_count,
                        "objects_read": objects_read,
                        "reason": reason,
                    }
                )

            collection["trails_collected"] = sum(
                1 for t in collection["trails"] if t["status"] == "collected"
            )
            collection["buckets"] = buckets
            collection["records"] = mgmt_w.count
            if mgmt_w.count:
                collection["s3_files"] = [mgmt_w.finalize()]
            if collection["trails_collected"]:
                self._log(
                    f"Collected logs from {collection['trails_collected']}/{s3_attempts} trail(s) "
                    f"across {len(buckets)} bucket(s)."
                )
        return [], [], collection

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
        writer=None,
        seen_event_ids: set[str] | None = None,
        max_records: int | None = None,
    ) -> tuple[int, dict]:
        trails = config.get("trails", [])
        if not any(configured_fn(t) for t in trails):
            return 0, {"configured": False, "records": 0}

        if not any(trail_is_logging_to_s3(t) for t in trails):
            if require_s3:
                gaps.append(
                    (
                        gap_name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "Event type enabled but trail does not deliver logs to S3.",
                    )
                )
            return 0, {"configured": True, "records": 0, "s3_logging": False}

        cap = max_records if max_records is not None else self.max_records(MAX_LOOKUP_RECORDS)
        combined_stats: dict = {"configured": True, "records": 0, "s3_logging": True}
        account_id = self.ctx.account_id
        before = writer.count if writer is not None else 0

        for trail in trails:
            if not configured_fn(trail) or not trail_is_logging_to_s3(trail):
                continue
            _, stats = collect_s3_trail_records(
                cf,
                trail,
                account_id,
                self.ctx.regions,
                start,
                end,
                categories,
                gaps,
                log=lambda msg: self._log(msg),
                max_records=cap,
                writer=writer,
                seen_event_ids=seen_event_ids,
            )
            rec_count = int(stats.get("records") or 0)
            self._merge_s3_bucket_stats(s3_by_bucket, trail, gap_name, rec_count, stats)
            for key in ("objects_scanned", "objects_read", "records", "truncated"):
                if key == "truncated":
                    combined_stats["truncated"] = combined_stats.get("truncated") or stats.get(
                        "truncated"
                    )
                else:
                    combined_stats[key] = combined_stats.get(key, 0) + stats.get(key, 0)

        if writer is not None:
            combined_stats["records"] = writer.count - before
        else:
            combined_stats["records"] = combined_stats.get("records", 0)
        record_count = int(combined_stats["records"])
        if require_s3 and combined_stats.get("configured") and record_count == 0:
            gaps.append(
                (
                    gap_name,
                    GapReason.NOT_PRESENT,
                    f"No {gap_name.replace('_', ' ')} log records in window (check S3 path/permissions).",
                )
            )
        return record_count, combined_stats

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
        mgmt_count: int,
        mgmt_source: str,
        lookup_insight_count: int,
        insight_s3_count: int,
        data_count: int,
        network_count: int,
        s3_by_bucket: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        mgmt_from_s3 = mgmt_source == "s3_logs"
        lookup_management = 0 if mgmt_from_s3 else mgmt_count
        s3_management = mgmt_count if mgmt_from_s3 else 0
        lookup_total = lookup_management + lookup_insight_count
        s3_total = s3_management + insight_s3_count + data_count + network_count
        return {
            "trail_count": len(trails),
            "trails": [self._trail_summary(t) for t in trails],
            "management_source": mgmt_source,
            "events": {
                "lookup_api": {
                    "management": lookup_management,
                    "insight": lookup_insight_count,
                    "total": lookup_total,
                },
                "s3": {
                    "total": s3_total,
                    "management": s3_management,
                    "data": data_count,
                    "insight": insight_s3_count,
                    "network_activity": network_count,
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
