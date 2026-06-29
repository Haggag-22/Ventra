"""RDS CloudWatch log-export collector.

RDS can export engine logs (error, general, slowquery, audit, etc.) to CloudWatch log groups
under ``/aws/rds/instance/<id>/<log-type>``. This collector records which instances export
which log types and pulls those CloudWatch events — not logs stored inside the database.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_rds_log_targets
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from ..common.cw_logs import collect_cw_log_events

DEFAULT_WINDOW_DAYS = 7
MAX_RECORDS = DEFAULT_MAX_RECORDS


def _log_group_for_instance(instance_id: str, log_type: str) -> str:
    return f"/aws/rds/instance/{instance_id}/{log_type}"


class RdsLogsCollector(Collector):
    name = "rds"
    priority = 2
    description = "RDS engine logs exported to CloudWatch Logs (not in-DB logs)."
    required_actions = (
        "rds:DescribeDBInstances",
        "logs:FilterLogEvents",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        cap = self.max_records(MAX_RECORDS)

        instances = filter_rds_log_targets(self._discover_instances(cf, gaps), params)
        if not instances:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("rds", GapReason.NOT_PRESENT, "No RDS instances in scope.")],
                notes="No RDS instances found.",
            )

        exporting = [i for i in instances if i.get("log_exports")]
        not_exporting = [i for i in instances if not i.get("log_exports")]
        if not_exporting:
            names = ", ".join(i["instance_id"] for i in not_exporting[:10])
            more = f" (+{len(not_exporting) - 10} more)" if len(not_exporting) > 10 else ""
            gaps.append(
                (
                    "rds",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"CloudWatch log export disabled on {len(not_exporting)}/{len(instances)} "
                    f"instance(s): {names}{more}.",
                )
            )

        log_targets: list[dict[str, Any]] = []
        for inst in exporting:
            for log_type in inst["log_exports"]:
                log_targets.append(
                    {
                        "region": inst["region"],
                        "instance_id": inst["instance_id"],
                        "instance_arn": inst["instance_arn"],
                        "engine": inst.get("engine", ""),
                        "log_type": log_type,
                        "log_group": _log_group_for_instance(inst["instance_id"], log_type),
                    }
                )

        per_target: list[dict[str, Any]] = []
        record_count = 0
        event_files: list = []
        with self.open_jsonl("events.jsonl.gz") as writer:
            for target in log_targets:
                self._log(
                    f"Reading {target['log_type']} logs for {target['instance_id']} "
                    f"({target['log_group']})…"
                )
                before = writer.count
                _, stats = collect_cw_log_events(
                    cf,
                    target["region"],
                    target["log_group"],
                    start,
                    end,
                    gaps,
                    "rds",
                    max_records=cap,
                    writer=writer,
                    record_extra={
                        "_ventra_db_instance_id": target.get("instance_id", ""),
                        "_ventra_db_instance_arn": target.get("instance_arn", ""),
                        "_ventra_log_type": target.get("log_type", ""),
                    },
                )
                per_target.append({**target, "records": writer.count - before, **stats})
            record_count = writer.count
            if writer.count:
                event_files.append(writer.finalize())

        config = {
            "instances": instances,
            "exporting_count": len(exporting),
            "not_exporting_count": len(not_exporting),
            "log_targets": log_targets,
            "collection": per_target,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": params,
        }
        files = [self.write_json(config, "config.json"), *event_files]
        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "instances": len(instances),
                "exporting": len(exporting),
                "window": {"since": start.isoformat(), "until": end.isoformat()},
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif log_targets:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(("rds", GapReason.NOT_PRESENT, "No RDS log records in window."))
        else:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} log record(s) from {len(exporting)}/{len(instances)} exporting instance(s).",
        )

    def _discover_instances(self, cf, gaps) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for region in self.ctx.regions:
            try:
                for db in cf.paginate("rds", region, "describe_db_instances", "DBInstances"):
                    instance_id = db.get("DBInstanceIdentifier", "")
                    out.append(
                        {
                            "region": region,
                            "instance_id": instance_id,
                            "instance_arn": db.get("DBInstanceArn", ""),
                            "engine": db.get("Engine", ""),
                            "log_exports": list(db.get("EnabledCloudwatchLogsExports") or []),
                        }
                    )
            except AccessDenied as exc:
                gaps.append(("rds", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except (ServiceNotEnabled, ClientError):
                continue
        return out
