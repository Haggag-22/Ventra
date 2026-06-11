"""CloudTrail collector — the control-plane backbone of cloud IR.

Captures:
  1. **Trail configuration** — trails, selectors (management / data / network / insights),
     log validation, and S3 delivery settings.
  2. **Management events** — via LookupEvents (portable, ~90-day lookback).
  3. **Insight events** — via LookupEvents and S3 log files when Insights is enabled.
  4. **Data events** — from the trail's S3 log files when data events are enabled.
  5. **Network activity events** — from the trail's S3 log files when enabled.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled
from .cloudtrail_s3 import (
    DATA_CATEGORIES,
    INSIGHT_CATEGORIES,
    NETWORK_CATEGORIES,
    collect_s3_trail_records,
    coverage_summary,
    data_events_configured,
    insight_events_configured,
    lookup_event_category,
    merge_dedupe,
    network_activity_configured,
    trail_is_logging_to_s3,
)

# Bound the in-memory LookupEvents pull so a busy account can't exhaust a CloudShell.
MAX_LOOKUP_RECORDS = 200_000


class CloudTrailCollector(Collector):
    name = "cloudtrail"
    tier = 1
    description = (
        "CloudTrail trail config, management and insight events (LookupEvents), "
        "and data / network-activity events from S3 logs."
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

        mgmt_records, lookup_insight_records = self._collect_lookup_events(cf, gaps, start, end)
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
        )
        insight_records = merge_dedupe(lookup_insight_records, insight_s3_records)

        data_records, data_stats = self._collect_s3_category(
            cf, config, gaps, start, end, DATA_CATEGORIES, data_events_configured, "data_events"
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
            "insight_events": insight_stats,
            "data_events": data_stats,
            "network_activity": network_stats,
        }

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
            }
        )

        notes = (
            f"{len(mgmt_records)} management, {len(insight_records)} insight, "
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
                    ev["_harbor_region"] = region
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
