"""CloudWatch Logs collector — pull events from selected log groups.

Use this when the IR target is raw CloudWatch evidence (application logs, custom
groups, or delivery destinations for other AWS services). Domain collectors
(vpc_flow, lambda_logs, eks_audit, …) remain the preferred path when the source
service is known; this collector is the generic fallback.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS, records_unlimited
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window, param_strings
from collector.lib.scoping import normalize_log_group_ref, normalize_log_group_refs

from ..common.cw_logs import collect_cw_log_events, parse_log_group_arn

DEFAULT_WINDOW_DAYS = 14
MAX_RECORDS = DEFAULT_MAX_RECORDS


class CloudWatchCollector(Collector):
    name = "cloudwatch"
    priority = 1
    description = (
        "CloudWatch Logs events from selected log groups (by name, ARN, or name prefix). "
        "Prefer domain collectors (vpc_flow, lambda_logs, eks_audit) when the source "
        "service is known; use this for custom or cross-service CloudWatch evidence."
    )
    required_actions = (
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        cap = self.max_records(MAX_RECORDS)

        requested = normalize_log_group_refs(param_strings(params, "log_group_names"))
        prefixes = param_strings(params, "log_group_name_prefix")
        stream_prefixes = param_strings(params, "log_stream_name_prefix")
        stream_prefix = stream_prefixes[0] if stream_prefixes else None

        # Optional region hints embedded in ARNs (e.g. arn:aws:logs:us-east-2:…:log-group:…)
        arn_regions: dict[str, str] = {}
        for raw in param_strings(params, "log_group_names"):
            parsed = parse_log_group_arn(raw) if ":log-group:" in raw else None
            if parsed:
                region, group = parsed
                if region and group:
                    arn_regions[group] = region

        discovered = self._discover_log_groups(cf, gaps, prefixes=prefixes)
        targets = self._resolve_targets(discovered, requested, arn_regions)

        if not targets:
            detail = (
                "No CloudWatch log groups matched. Set CloudWatch log groups "
                "(log_group_names) or a log group name prefix."
                if (requested or prefixes)
                else "No CloudWatch log groups found in the selected regions. "
                "Pass log_group_names to target specific groups."
            )
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("cloudwatch", GapReason.NOT_PRESENT, detail)],
                notes=detail,
            )

        per_group: list[dict[str, Any]] = []
        record_count = 0
        files: list = []
        with self.open_jsonl("events.jsonl.gz") as writer:
            for target in targets:
                if not records_unlimited(cap) and writer.count >= cap:
                    break
                remaining = cap - writer.count if not records_unlimited(cap) else cap
                group = target["log_group"]
                region = target["region"]
                self._log(f"Reading CloudWatch log group {group} in {region}…")
                before = writer.count
                _, stats = collect_cw_log_events(
                    cf,
                    region,
                    group,
                    start,
                    end,
                    gaps,
                    "cloudwatch",
                    stream_prefix=stream_prefix,
                    max_records=remaining,
                    writer=writer,
                )
                per_group.append(
                    {
                        **target,
                        "records": writer.count - before,
                        "truncated": bool(stats.get("truncated")),
                    }
                )
            record_count = writer.count
            if writer.count:
                files.append(writer.finalize())

        config = {
            "log_groups": discovered,
            "targets": targets,
            "collection": per_group,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": {
                "log_group_names": requested,
                "log_group_name_prefix": prefixes,
                "log_stream_name_prefix": stream_prefixes,
            },
            "collection_summary": {
                "log_group_count": len(targets),
                "log_groups": [
                    {
                        "name": g["log_group"],
                        "region": g["region"],
                        "records": g.get("records", 0),
                        "arn": g.get("arn", ""),
                    }
                    for g in per_group
                ],
                "records": record_count,
            },
        }
        files.insert(0, self.write_json(config, "config.json"))
        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "log_groups": len(targets),
                "window": {"since": start.isoformat(), "until": end.isoformat()},
                "collection_summary": config["collection_summary"],
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            if not gaps:
                gaps.append(
                    (
                        "cloudwatch",
                        GapReason.NOT_PRESENT,
                        "No CloudWatch log events in the selected window.",
                    )
                )

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=(f"{record_count:,} event(s) from {len(targets)} CloudWatch log group(s)."),
        )

    def _discover_log_groups(
        self,
        cf,
        gaps: list[tuple[str, GapReason, str]],
        *,
        prefixes: list[str],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        prefix_list = prefixes or [""]
        for region in self.ctx.regions:
            for prefix in prefix_list:
                kwargs: dict[str, Any] = {}
                if prefix:
                    kwargs["logGroupNamePrefix"] = prefix
                try:
                    for lg in cf.paginate(
                        "logs",
                        region,
                        "describe_log_groups",
                        "logGroups",
                        **kwargs,
                    ):
                        name = normalize_log_group_ref(str(lg.get("logGroupName") or ""))
                        if not name:
                            continue
                        key = f"{region}::{name}"
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append(
                            {
                                "region": region,
                                "log_group": name,
                                "arn": lg.get("arn") or lg.get("logGroupArn") or "",
                                "stored_bytes": lg.get("storedBytes"),
                                "retention_days": lg.get("retentionInDays"),
                            }
                        )
                except AccessDenied as exc:
                    gaps.append(("cloudwatch", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                except (ServiceNotEnabled, ClientError):
                    continue
        return out

    def _resolve_targets(
        self,
        discovered: list[dict[str, Any]],
        requested: list[str],
        arn_regions: dict[str, str],
    ) -> list[dict[str, Any]]:
        if not requested:
            return list(discovered)

        by_key = {f"{g['region']}::{g['log_group']}": g for g in discovered}
        by_name: dict[str, list[dict[str, Any]]] = {}
        for g in discovered:
            by_name.setdefault(g["log_group"], []).append(g)

        targets: list[dict[str, Any]] = []
        seen: set[str] = set()
        for name in requested:
            preferred_region = arn_regions.get(name)
            candidates = by_name.get(name, [])
            if preferred_region:
                preferred = [c for c in candidates if c["region"] == preferred_region]
                if preferred:
                    candidates = preferred
                elif not candidates:
                    # Group not listed by DescribeLogGroups (denied/prefix miss) — still try.
                    candidates = [
                        {
                            "region": preferred_region,
                            "log_group": name,
                            "arn": "",
                            "stored_bytes": None,
                            "retention_days": None,
                        }
                    ]
            if not candidates:
                # Fall back to every in-scope region when the group wasn't discovered.
                for region in self.ctx.regions:
                    candidates.append(
                        {
                            "region": region,
                            "log_group": name,
                            "arn": "",
                            "stored_bytes": None,
                            "retention_days": None,
                        }
                    )
            for c in candidates:
                key = f"{c['region']}::{c['log_group']}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(c)
        return targets
