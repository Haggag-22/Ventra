"""Cloud Armor (WAF) collector.

Captures security policy inventory and HTTP(S) load balancer request logs where Cloud
Armor enforcement is recorded (``jsonPayload.enforcedSecurityPolicy``). Policies without
attached backends still appear in ``config.json``; missing request logs are recorded as gaps.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_by_name_or_id, gcp_logging_filter_extension
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled

DEFAULT_WINDOW_DAYS = 14
ARMOR_LOG_FILTER = (
    '(logName:("compute.googleapis.com%2Frequests" OR "loadbalancing.googleapis.com%2Frequests")) '
    "AND jsonPayload.enforcedSecurityPolicy.name:*"
)


class CloudArmorCollector(Collector):
    name = "cloud_armor"
    priority = 1
    description = "Cloud Armor security policy inventory and enforced request logs."
    required_actions = (
        "compute.securityPolicies.list",
        "logging.logEntries.list",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        projects = self.ctx.project_ids
        if not projects:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("cloud_armor", GapReason.NOT_PRESENT, "No projects in scope.")],
            )

        policies: list[dict[str, Any]] = []
        for project_id in projects:
            try:
                listed = cf.compute_security_policies(project_id)
            except GcpAccessDenied as exc:
                gaps.append(("cloud_armor", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}"))
                continue
            except GcpServiceNotEnabled:
                continue
            for policy in listed:
                policy["_ventra_project_id"] = project_id
                policies.append(policy)

        policies = filter_by_name_or_id(
            policies,
            params,
            name_keys=("name",),
            id_keys=("id",),
            name_param="security_policy_names",
            id_param="security_policy_ids",
        )

        if not policies:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("cloud_armor", GapReason.NOT_PRESENT, "No Cloud Armor security policies in scope.")],
                notes="No Cloud Armor policies found.",
            )

        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        scoped = gcp_logging_filter_extension(params)
        log_filter = f"({ARMOR_LOG_FILTER})"
        if scoped:
            log_filter = f"({ARMOR_LOG_FILTER}) AND ({scoped})"

        cap = self.max_records(MAX_RECORDS)
        record_count = 0
        per_project: list[dict[str, Any]] = []
        with self.open_jsonl("events.jsonl.gz") as writer:
            for project_id in projects:
                before = record_count
                try:
                    for entry in cf.list_log_entries(
                        project_id,
                        log_filter=log_filter,
                        start=start,
                        end=end,
                        max_records=cap - record_count if record_count < cap else 0,
                    ):
                        writer.write_record({**entry, "_ventra_project_id": project_id})
                        record_count += 1
                        if record_count >= cap:
                            break
                except GcpAccessDenied as exc:
                    gaps.append(("cloud_armor", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}"))
                except GcpServiceNotEnabled as exc:
                    gaps.append(
                        ("cloud_armor", GapReason.SERVICE_NOT_ENABLED, f"{project_id}: {exc.message}")
                    )
                per_project.append({"project_id": project_id, "records": record_count - before})

        if record_count >= cap:
            self.append_truncation_gap(
                gaps,
                "cloud_armor",
                cap,
                f"Truncated at {cap:,} records; narrow the window or use enterprise profile.",
            )

        if policies and record_count == 0:
            gaps.append(
                (
                    "cloud_armor",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    "Security policies exist but no enforced request logs in window — "
                    "enable HTTP(S) load balancer logging with Cloud Armor attached.",
                )
            )

        config = {
            "security_policies": policies,
            "projects": per_project,
            "log_filter": log_filter,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": params,
        }
        files = [self.write_json(config, "config.json")]
        if record_count:
            files.append(writer.finalize())

        self.write_meta(
            {
                "source": self.name,
                "security_policies": len(policies),
                "records": record_count,
            }
        )

        status = SourceStatus.COLLECTED if policies else SourceStatus.EMPTY
        if gaps and record_count:
            status = SourceStatus.PARTIAL
        elif gaps and not record_count:
            status = SourceStatus.PARTIAL if policies else SourceStatus.EMPTY

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(policies),
            gaps=gaps,
            notes=f"{len(policies)} security policy/policies; {record_count} enforced request log(s).",
        )
