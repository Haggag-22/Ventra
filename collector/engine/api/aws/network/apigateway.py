"""API Gateway access-log collector.

REST and HTTP API stage access logs land in CloudWatch when ``accessLogSettings`` /
``AccessLogSettings`` points at a log group. This collector discovers those stages,
records stages without access logging as gaps, and pulls log events for the case window.
Stages that ship to Kinesis or Firehose are recorded as out-of-scope gaps.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_apigateway_stages
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from ..common.cw_logs import collect_cw_log_events, parse_log_group_arn

DEFAULT_WINDOW_DAYS = 7
MAX_RECORDS = DEFAULT_MAX_RECORDS


class ApigatewayCollector(Collector):
    name = "apigateway"
    priority = 2
    description = "API Gateway REST/HTTP API stage access logs from CloudWatch."
    required_actions = (
        "apigateway:GET",
        "logs:FilterLogEvents",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        cap = self.max_records(MAX_RECORDS)

        stages = filter_apigateway_stages(self._discover_stages(cf, gaps), params)
        if not stages:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("apigateway", GapReason.NOT_PRESENT, "No API Gateway stages in scope.")],
                notes="No API Gateway stages found.",
            )

        logged = [s for s in stages if s.get("log_group")]
        unlogged = [s for s in stages if not s.get("log_group")]
        non_cw = [s for s in stages if s.get("destination_type") == "non_cloudwatch"]

        if unlogged:
            names = ", ".join(f"{s['api_name']}/{s['stage_name']}" for s in unlogged[:10])
            more = f" (+{len(unlogged) - 10} more)" if len(unlogged) > 10 else ""
            gaps.append(
                (
                    "apigateway",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"Access logging disabled on {len(unlogged)}/{len(stages)} "
                    f"stage(s): {names}{more}.",
                )
            )
        for stage in non_cw:
            gaps.append(
                (
                    "apigateway",
                    GapReason.OUT_OF_SCOPE,
                    f"Stage {stage['api_name']}/{stage['stage_name']} delivers access logs to "
                    f"{stage.get('destination_arn', 'a non-CloudWatch destination')} — "
                    "collect from that destination manually.",
                )
            )

        per_stage: list[dict[str, Any]] = []
        record_count = 0
        event_files: list = []
        with self.open_jsonl("events.jsonl.gz") as writer:
            for stage in logged:
                self._log(
                    f"Reading access logs for {stage['api_name']}/{stage['stage_name']} "
                    f"({stage['log_group']})…"
                )
                before = writer.count
                _, stats = collect_cw_log_events(
                    cf,
                    stage["region"],
                    stage["log_group"],
                    start,
                    end,
                    gaps,
                    "apigateway",
                    max_records=cap,
                    writer=writer,
                    record_extra={
                        "_ventra_api_id": stage.get("api_id", ""),
                        "_ventra_api_name": stage.get("api_name", ""),
                        "_ventra_stage_name": stage.get("stage_name", ""),
                        "_ventra_api_type": stage.get("api_type", ""),
                    },
                )
                per_stage.append({**stage, "records": writer.count - before, **stats})
            record_count = writer.count
            if writer.count:
                event_files.append(writer.finalize())

        config = {
            "stages": stages,
            "logging_enabled_count": len(logged),
            "logging_disabled_count": len(unlogged),
            "collection": per_stage,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": params,
        }
        files = [self.write_json(config, "config.json"), *event_files]
        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "stages": len(stages),
                "logging_enabled": len(logged),
                "window": {"since": start.isoformat(), "until": end.isoformat()},
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif logged:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            if not any(g[1] == GapReason.NOT_PRESENT for g in gaps):
                gaps.append(
                    ("apigateway", GapReason.NOT_PRESENT, "No access-log records in window.")
                )
        else:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} access-log record(s) from {len(logged)}/{len(stages)} logged stage(s).",
        )

    def _discover_stages(self, cf, gaps) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for region in self.ctx.regions:
            try:
                for api in cf.paginate("apigateway", region, "get_rest_apis", "items"):
                    api_id = api.get("id", "")
                    api_name = api.get("name", api_id)
                    try:
                        stages = cf.call(
                            "apigateway", region, "get_stages", restApiId=api_id
                        ).get("item", [])
                    except (AccessDenied, ServiceNotEnabled, ClientError):
                        continue
                    for stage in stages:
                        out.append(
                            self._stage_entry(
                                region,
                                api_id,
                                api_name,
                                stage.get("stageName", ""),
                                "rest",
                                (stage.get("accessLogSettings") or {}).get("destinationArn", ""),
                            )
                        )
            except (AccessDenied, ServiceNotEnabled, ClientError) as exc:
                if isinstance(exc, AccessDenied):
                    gaps.append(("apigateway", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue

            try:
                for api in cf.paginate("apigatewayv2", region, "get_apis", "Items"):
                    api_id = api.get("ApiId", "")
                    api_name = api.get("Name", api_id)
                    try:
                        stages = cf.call(
                            "apigatewayv2", region, "get_stages", ApiId=api_id
                        ).get("Items", [])
                    except (AccessDenied, ServiceNotEnabled, ClientError):
                        continue
                    for stage in stages:
                        out.append(
                            self._stage_entry(
                                region,
                                api_id,
                                api_name,
                                stage.get("StageName", ""),
                                str(api.get("ProtocolType", "HTTP")).lower(),
                                (stage.get("AccessLogSettings") or {}).get("DestinationArn", ""),
                            )
                        )
            except (AccessDenied, ServiceNotEnabled, ClientError):
                pass
        return out

    @staticmethod
    def _stage_entry(
        region: str,
        api_id: str,
        api_name: str,
        stage_name: str,
        api_type: str,
        destination_arn: str,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "region": region,
            "api_id": api_id,
            "api_name": api_name,
            "stage_name": stage_name,
            "api_type": api_type,
            "destination_arn": destination_arn,
            "log_group": "",
            "destination_type": "",
        }
        if not destination_arn:
            return entry
        if ":logs:" in destination_arn and ":log-group:" in destination_arn:
            parsed = parse_log_group_arn(destination_arn)
            if parsed:
                entry["log_group"] = parsed[1]
                entry["destination_type"] = "cloudwatch"
            return entry
        entry["destination_type"] = "non_cloudwatch"
        return entry
