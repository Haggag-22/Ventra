"""Lambda execution-log collector.

Lambda functions emit platform and application logs to CloudWatch log groups named
``/aws/lambda/<function>``. This collector inventories in-scope functions, records which
have a log group present, and pulls log events for the case window via FilterLogEvents.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_lambda_log_targets
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from ..common.cw_logs import collect_cw_log_events

DEFAULT_WINDOW_DAYS = 7
MAX_RECORDS = DEFAULT_MAX_RECORDS
LOG_GROUP_PREFIX = "/aws/lambda/"


class LambdaLogsCollector(Collector):
    name = "lambda_logs"
    priority = 2
    description = "Lambda function execution logs from CloudWatch Logs."
    required_actions = (
        "lambda:ListFunctions",
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        cap = self.max_records(MAX_RECORDS)

        targets = filter_lambda_log_targets(self._discover_targets(cf, gaps), params)
        if not targets:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("lambda_logs", GapReason.NOT_PRESENT, "No Lambda functions in scope.")],
                notes="No Lambda functions found.",
            )

        with_groups = [t for t in targets if t.get("log_group_exists")]
        without_groups = [t for t in targets if not t.get("log_group_exists")]
        if without_groups:
            names = ", ".join(t["function_name"] for t in without_groups[:10])
            more = f" (+{len(without_groups) - 10} more)" if len(without_groups) > 10 else ""
            gaps.append(
                (
                    "lambda_logs",
                    GapReason.NOT_PRESENT,
                    f"No CloudWatch log group yet for {len(without_groups)}/{len(targets)} "
                    f"function(s) (never invoked or logs disabled): {names}{more}.",
                )
            )

        per_function: list[dict[str, Any]] = []
        record_count = 0
        event_files: list = []
        with self.open_jsonl("events.jsonl.gz") as writer:
            for target in with_groups:
                group = target["log_group"]
                self._log(f"Reading logs for {target['function_name']} ({group})…")
                before = writer.count
                _, stats = collect_cw_log_events(
                    cf,
                    target["region"],
                    group,
                    start,
                    end,
                    gaps,
                    "lambda_logs",
                    max_records=cap,
                    writer=writer,
                    record_extra={
                        "_ventra_function_name": target.get("function_name", ""),
                        "_ventra_function_arn": target.get("function_arn", ""),
                    },
                )
                per_function.append({**target, "records": writer.count - before, **stats})
            record_count = writer.count
            if writer.count:
                event_files.append(writer.finalize())

        config = {
            "functions": targets,
            "log_group_present_count": len(with_groups),
            "log_group_missing_count": len(without_groups),
            "collection": per_function,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": params,
        }
        files = [self.write_json(config, "config.json"), *event_files]
        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "functions": len(targets),
                "with_log_groups": len(with_groups),
                "window": {"since": start.isoformat(), "until": end.isoformat()},
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif with_groups:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(
                ("lambda_logs", GapReason.NOT_PRESENT, "No Lambda log records in window.")
            )
        else:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} log record(s) from {len(with_groups)}/{len(targets)} function(s).",
        )

    def _discover_targets(self, cf, gaps) -> list[dict[str, Any]]:
        existing_groups: set[str] = set()
        for region in self.ctx.regions:
            try:
                for lg in cf.paginate(
                    "logs",
                    region,
                    "describe_log_groups",
                    "logGroups",
                    logGroupNamePrefix=LOG_GROUP_PREFIX,
                ):
                    name = lg.get("logGroupName", "")
                    if name:
                        existing_groups.add(f"{region}::{name}")
            except (AccessDenied, ServiceNotEnabled, ClientError):
                continue

        out: list[dict[str, Any]] = []
        for region in self.ctx.regions:
            try:
                for fn in cf.paginate("lambda", region, "list_functions", "Functions"):
                    name = fn.get("FunctionName", "")
                    arn = fn.get("FunctionArn", "")
                    group = f"{LOG_GROUP_PREFIX}{name}"
                    key = f"{region}::{group}"
                    out.append(
                        {
                            "region": region,
                            "function_name": name,
                            "function_arn": arn,
                            "log_group": group,
                            "log_group_exists": key in existing_groups,
                            "runtime": fn.get("Runtime", ""),
                        }
                    )
            except AccessDenied as exc:
                gaps.append(("lambda_logs", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except (ServiceNotEnabled, ClientError):
                continue
        return out
