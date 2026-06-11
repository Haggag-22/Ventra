"""VPC Flow Logs collector.

Flow logs are the exfiltration lens — top talkers, rejected flows, egress volume to public
IPs. This collector first establishes *whether flow logging exists at all* (a very common
gap), records where it lands (CloudWatch Logs vs S3), and pulls recent records from
CloudWatch Logs when that's the destination. S3-resident flow logs are pulled by the S3 log
path given the bucket; here we capture configuration + CloudWatch records for portability.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...common.base import Collector
from ...common.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class VpcFlowCollector(Collector):
    name = "vpc_flow"
    tier = 1
    description = "VPC Flow Logs configuration + recent CloudWatch flow records."
    required_actions = (
        "ec2:DescribeFlowLogs",
        "ec2:DescribeVpcs",
        "logs:FilterLogEvents",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        flow_configs: list[dict] = []
        cw_log_groups: set[str] = set()

        for region in self.ctx.regions:
            try:
                fls = list(cf.paginate("ec2", region, "describe_flow_logs", "FlowLogs"))
            except AccessDenied as exc:
                gaps.append(("vpc_flow", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue
            for fl in fls:
                fl["_harbor_region"] = region
                flow_configs.append(fl)
                if fl.get("LogDestinationType") == "cloud-watch-logs" and fl.get("LogGroupName"):
                    cw_log_groups.add(f"{region}::{fl['LogGroupName']}")

        if not flow_configs:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[
                    (
                        "vpc_flow",
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "No VPC Flow Logs configured in any in-scope region. "
                        "Exfiltration volume cannot be quantified for this window.",
                    )
                ],
                notes="No flow logging configured — recorded as a gap (this is evidence).",
            )

        self.write_json({"flow_logs": flow_configs}, "config.json")

        # Pull recent records from CloudWatch-destined flow logs.
        window = self.ctx.time_window
        end = window.until or datetime.now(UTC)
        start = window.since or (end - timedelta(days=14))
        records = []
        for entry in sorted(cw_log_groups):
            region, group = entry.split("::", 1)
            try:
                for ev in cf.paginate(
                    "logs", region, "filter_log_events", "events",
                    logGroupName=group,
                    startTime=int(start.timestamp() * 1000),
                    endTime=int(end.timestamp() * 1000),
                ):
                    ev["_harbor_region"] = region
                    ev["_harbor_log_group"] = group
                    records.append(ev)
            except AccessDenied as exc:
                gaps.append(("vpc_flow_cw", GapReason.ACCESS_DENIED, exc.message))
            except ServiceNotEnabled:
                continue

        files = [self.write_json({"flow_logs": flow_configs}, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        status = SourceStatus.COLLECTED if records else SourceStatus.PARTIAL
        if not records:
            gaps.append(
                (
                    "vpc_flow",
                    GapReason.NOT_PRESENT,
                    "Flow logs configured but deliver to S3; pull from the log bucket for records.",
                )
            )
        self.write_meta(
            {
                "source": self.name,
                "flow_log_configs": len(flow_configs),
                "cloudwatch_records": len(records),
                "destinations": sorted({f.get("LogDestinationType") for f in flow_configs}),
            }
        )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(flow_configs)} flow-log config(s); {len(records)} CW records.",
        )
