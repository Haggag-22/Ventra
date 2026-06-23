"""Route53 Resolver query-log collector."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from ..common.s3_logs import bucket_region, collect_s3_line_records, slash_day_prefixes

DEFAULT_WINDOW_DAYS = 7
MAX_RECORDS = DEFAULT_MAX_RECORDS


class Route53ResolverCollector(Collector):
    name = "route53_resolver"
    priority = 2
    description = "Route53 Resolver DNS query logs from S3 or CloudWatch destinations."
    required_actions = (
        "route53resolver:ListResolverQueryLogConfigs",
        "route53resolver:ListResolverQueryLogConfigAssociations",
        "logs:FilterLogEvents",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        window = self.ctx.time_window
        start = window.since or (datetime.now(UTC) - timedelta(days=DEFAULT_WINDOW_DAYS))
        end = window.until or datetime.now(UTC)
        cap = self.max_records(MAX_RECORDS)

        configs, associations = self._discover(cf, gaps)
        if not configs:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [
                    (
                        "route53_resolver",
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "Resolver query logging is not configured in any region.",
                    )
                ],
                notes="No resolver query-log configs — recorded as a gap.",
            )

        vpcs_by_config: dict[str, list[str]] = {}
        for assoc in associations:
            cid = assoc.get("ResolverQueryLogConfigId", "")
            rid = assoc.get("ResourceId", "")
            if cid and rid:
                vpcs_by_config.setdefault(cid, []).append(rid)

        per_config: list[dict] = []
        record_count = 0
        event_files: list = []
        with self.open_jsonl("events.jsonl.gz") as writer:
            for config in configs:
                dest = str(config.get("DestinationArn") or "")
                cid = config.get("Id", "")
                vpcs = vpcs_by_config.get(cid, [])
                entry: dict[str, Any] = {
                    "id": cid,
                    "name": config.get("Name", ""),
                    "region": config.get("_ventra_region", ""),
                    "destination_arn": dest,
                    "vpcs": vpcs,
                    "records": 0,
                }
                before = writer.count
                if dest.startswith("arn:aws:s3"):
                    self._from_s3(cf, dest, vpcs, start, end, gaps, writer=writer, max_records=cap)
                elif ":logs:" in dest:
                    self._from_cloudwatch(
                        cf, config, dest, start, end, gaps, writer=writer, max_records=cap
                    )
                else:
                    gaps.append(
                        (
                            "route53_resolver",
                            GapReason.OUT_OF_SCOPE,
                            f"Config {cid} delivers to Firehose ({dest}) — streamed logs cannot "
                            "be read retrospectively; collect from the Firehose destination.",
                        )
                    )
                entry["records"] = writer.count - before
                per_config.append(entry)
            record_count = writer.count
            if writer.count:
                event_files.append(writer.finalize())

        config_doc = {
            "query_log_configs": per_config,
            "associations": associations,
            "window": window.to_manifest(),
        }
        files = [self.write_json(config_doc, "config.json"), *event_files]
        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "configs": len(configs),
                "window": window.to_manifest(),
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            if not gaps:
                gaps.append(
                    (
                        "route53_resolver",
                        GapReason.NOT_PRESENT,
                        "Query logging configured but no records in window.",
                    )
                )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=f"{record_count} DNS query record(s) from {len(configs)} config(s).",
        )

    def _discover(self, cf, gaps) -> tuple[list[dict], list[dict]]:
        configs: list[dict] = []
        associations: list[dict] = []
        for region in self.ctx.regions:
            try:
                for c in cf.paginate(
                    "route53resolver",
                    region,
                    "list_resolver_query_log_configs",
                    "ResolverQueryLogConfigs",
                ):
                    c["_ventra_region"] = region
                    configs.append(c)
                for a in cf.paginate(
                    "route53resolver",
                    region,
                    "list_resolver_query_log_config_associations",
                    "ResolverQueryLogConfigAssociations",
                ):
                    associations.append(a)
            except AccessDenied as exc:
                gaps.append(
                    ("route53_resolver", GapReason.ACCESS_DENIED, f"{region}: {exc.message}")
                )
            except (ServiceNotEnabled, ClientError):
                continue
        return configs, associations

    def _from_s3(
        self,
        cf,
        dest_arn: str,
        vpcs: list[str],
        start: datetime,
        end: datetime,
        gaps,
        *,
        writer=None,
        max_records: int = MAX_RECORDS,
    ) -> None:
        path = dest_arn.split(":::", 1)[-1]
        bucket, _, prefix = path.partition("/")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        region = bucket_region(cf, bucket)
        for vpc in vpcs:
            base = f"{prefix}AWSLogs/{self.ctx.account_id}/vpcdnsquerylogs/{vpc}/"

            def line_to_record(key: str, line: str, _vpc: str = vpc) -> dict[str, Any] | None:
                rec = _parse_json_line(line)
                if rec is None:
                    return None
                ts = _query_time(rec)
                if ts is not None and not (start <= ts <= end):
                    return None
                rec["_ventra_region"] = region
                rec["_ventra_s3_bucket"] = bucket
                rec["_ventra_log_key"] = key
                rec["_ventra_vpc_id"] = _vpc
                return rec

            collect_s3_line_records(
                cf,
                region,
                bucket,
                slash_day_prefixes(base, start, end),
                line_to_record,
                gaps,
                "route53_resolver",
                max_records=max_records,
                writer=writer,
            )

    @staticmethod
    def _from_cloudwatch(
        cf,
        config: dict,
        dest_arn: str,
        start: datetime,
        end: datetime,
        gaps,
        *,
        writer=None,
        max_records: int = MAX_RECORDS,
    ) -> None:
        from collector.lib.limits import records_unlimited

        parts = dest_arn.split(":log-group:", 1)
        if len(parts) != 2:
            return
        group = parts[1].split(":")[0]
        region = config.get("_ventra_region") or dest_arn.split(":")[3]
        count = writer.count if writer is not None else 0
        try:
            for ev in cf.paginate(
                "logs",
                region,
                "filter_log_events",
                "events",
                logGroupName=group,
                startTime=int(start.timestamp() * 1000),
                endTime=int(end.timestamp() * 1000),
            ):
                if not records_unlimited(max_records) and count >= max_records:
                    if not records_unlimited(max_records):
                        gaps.append(
                            (
                                "route53_resolver",
                                GapReason.COLLECTOR_ERROR,
                                f"{group}: truncated at {max_records} records.",
                            )
                        )
                    break
                rec = _parse_json_line(ev.get("message", ""))
                if rec is None:
                    continue
                ts = _query_time(rec)
                if ts is not None and not (start <= ts <= end):
                    continue
                rec["_ventra_region"] = region
                rec["_ventra_log_group"] = group
                if writer is not None:
                    writer.write_record(rec)
                count += 1
        except AccessDenied as exc:
            gaps.append(("route53_resolver", GapReason.ACCESS_DENIED, f"{group}: {exc.message}"))
        except ServiceNotEnabled:
            pass


def _parse_json_line(line: str) -> dict[str, Any] | None:
    try:
        rec = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    return rec if isinstance(rec, dict) else None


def _query_time(rec: dict[str, Any]) -> datetime | None:
    ts = rec.get("query_timestamp", "")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
