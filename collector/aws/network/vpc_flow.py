"""VPC Flow Logs collector.

Flow logs are the exfiltration lens — top talkers, rejected flows, egress volume to public
IPs. This collector first establishes *whether flow logging exists at all* (a very common
gap), records where it lands (CloudWatch Logs vs S3), and which VPCs have no VPC-level flow
log. It then pulls recent records from *both* destinations: CloudWatch Logs (via
FilterLogEvents) and S3 (the default plain-text ``.log.gz`` delivery, parsed in
``vpc_flow_s3``). Records from either destination merge into the same normalized network
events.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled
from .vpc_flow_s3 import collect_s3_flow_records, flow_log_s3_target

# Bound the in-memory CloudWatch pull so a chatty VPC can't exhaust a CloudShell.
MAX_CW_RECORDS = 200_000


class VpcFlowCollector(Collector):
    name = "vpc_flow"
    priority = 1
    description = "VPC Flow Logs configuration + recent CloudWatch flow records."
    required_actions = (
        "ec2:DescribeFlowLogs",
        "ec2:DescribeVpcs",
        "logs:FilterLogEvents",
        "s3:ListBucket",
        "s3:GetObject",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        flow_configs: list[dict] = []
        vpcs: list[dict] = []
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
                fl["_ventra_region"] = region
                flow_configs.append(fl)
                if fl.get("LogDestinationType") == "cloud-watch-logs" and fl.get("LogGroupName"):
                    cw_log_groups.add(f"{region}::{fl['LogGroupName']}")
            try:
                for vpc in cf.paginate("ec2", region, "describe_vpcs", "Vpcs"):
                    vpc["_ventra_region"] = region
                    vpcs.append(vpc)
            except (AccessDenied, ServiceNotEnabled):
                pass

        # VPCs with no VPC-level flow log are themselves evidence of a visibility gap.
        # (Subnet/ENI-level logs may still cover parts of them — recorded for the analyst.)
        logged_resources = {fl.get("ResourceId") for fl in flow_configs}
        uncovered_vpcs = sorted(
            v["VpcId"] for v in vpcs if v.get("VpcId") and v["VpcId"] not in logged_resources
        )

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

        if uncovered_vpcs:
            gaps.append(
                (
                    "vpc_flow_coverage",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"{len(uncovered_vpcs)} VPC(s) without a VPC-level flow log: "
                    + ", ".join(uncovered_vpcs[:20]),
                )
            )

        # Pull recent records from CloudWatch-destined flow logs.
        window = self.ctx.time_window
        end = window.until or datetime.now(UTC)
        start = window.since or (end - timedelta(days=14))
        records: list[dict] = []
        truncated = False
        for entry in sorted(cw_log_groups):
            if truncated:
                break
            region, group = entry.split("::", 1)
            try:
                for ev in cf.paginate(
                    "logs", region, "filter_log_events", "events",
                    logGroupName=group,
                    startTime=int(start.timestamp() * 1000),
                    endTime=int(end.timestamp() * 1000),
                ):
                    if len(records) >= MAX_CW_RECORDS:
                        truncated = True
                        break
                    ev["_ventra_region"] = region
                    ev["_ventra_log_group"] = group
                    records.append(ev)
            except AccessDenied as exc:
                gaps.append(("vpc_flow_cw", GapReason.ACCESS_DENIED, exc.message))
            except ServiceNotEnabled:
                continue
        if truncated:
            gaps.append(
                (
                    "vpc_flow_cw",
                    GapReason.COLLECTOR_ERROR,
                    f"CloudWatch flow records truncated at {MAX_CW_RECORDS}; "
                    "narrow the window (--since/--until) for full coverage.",
                )
            )

        # Pull records from S3-delivering flow logs — the common production layout. The records
        # are structured the same way the normalizer expects, so they merge with CW records.
        account_id = self.ctx.account_id
        s3_flow_logs = [fl for fl in flow_configs if flow_log_s3_target(fl)]
        s3_records: list[dict] = []
        s3_objects_read = 0
        s3_truncated = False
        for fl in s3_flow_logs:
            self._log(f"Reading S3 flow logs for {fl.get('FlowLogId', '')}…")
            recs, s3_stats = collect_s3_flow_records(
                cf, fl, account_id, start, end, gaps, log=lambda msg: self._log(msg)
            )
            s3_records.extend(recs)
            s3_objects_read += int(s3_stats.get("objects_read") or 0)
            s3_truncated = s3_truncated or bool(s3_stats.get("truncated"))

        config_doc = {
            "flow_logs": flow_configs,
            "vpcs": vpcs,
            "vpcs_without_flow_logs": uncovered_vpcs,
        }
        files = [self.write_json(config_doc, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        if s3_records:
            files.append(self.write_jsonl(s3_records, "events_s3.jsonl.gz"))

        total_records = len(records) + len(s3_records)
        status = SourceStatus.COLLECTED if total_records else SourceStatus.PARTIAL
        if not total_records:
            if cw_log_groups and not s3_flow_logs:
                gaps.append(
                    (
                        "vpc_flow",
                        GapReason.NOT_PRESENT,
                        "CloudWatch-destined flow logs exist but held no records in the window.",
                    )
                )
            elif s3_flow_logs:
                gaps.append(
                    (
                        "vpc_flow",
                        GapReason.NOT_PRESENT,
                        "Flow logs deliver to S3 but no records were found in the window "
                        "(delivery can lag ~10 min after creation; also check path/permissions).",
                    )
                )
            else:
                gaps.append(
                    (
                        "vpc_flow",
                        GapReason.NOT_PRESENT,
                        "Flow logs configured but no records found in CloudWatch or S3.",
                    )
                )
        self.write_meta(
            {
                "source": self.name,
                "flow_log_configs": len(flow_configs),
                "vpcs": len(vpcs),
                "vpcs_without_flow_logs": len(uncovered_vpcs),
                "cloudwatch_records": len(records),
                "cloudwatch_truncated": truncated,
                "s3_records": len(s3_records),
                "s3_objects_read": s3_objects_read,
                "s3_truncated": s3_truncated,
                "records": total_records,
                "destinations": sorted({f.get("LogDestinationType") for f in flow_configs}),
            }
        )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=total_records,
            gaps=gaps,
            notes=(
                f"{len(flow_configs)} flow-log config(s); {len(records)} CW + "
                f"{len(s3_records)} S3 records; {len(uncovered_vpcs)} VPC(s) uncovered."
            ),
        )
