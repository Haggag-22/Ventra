"""GCP logging-posture collector — presence detection for log sources.

Mirrors AWS log_posture: for IR-critical log sources Ventra may not pull directly, this
records whether they are enabled and where they ship. Disabled logging is a forensic
finding; enabled logging tells the responder where to collect manually. Each check is
reported as a manifest gap named by its catalog id for the console Logs Coverage panel.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled

MAX_SUBNETS = 500
MAX_FIREWALLS = 500

_PLANNED_COLLECTOR = "Ventra collects flow/firewall logs when enabled — see vpc_flow / firewall_logs."


class LoggingPostureCollector(Collector):
    name = "logging_posture"
    priority = 2
    description = (
        "Logging posture for VPC Flow Logs, firewall rule logging, and Cloud Audit log sinks."
    )
    required_actions = (
        "compute.subnetworks.list",
        "compute.firewalls.list",
        "logging.sinks.list",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        projects = self.ctx.project_ids
        if not projects:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("logging_posture", GapReason.NOT_PRESENT, "No projects in scope.")],
            )

        posture: dict[str, Any] = {}
        checks = (
            ("vpc_flow_logs", self._check_vpc_flow_logs),
            ("firewall_rule_logging", self._check_firewall_logging),
            ("audit_log_sinks", self._check_audit_sinks),
        )
        for source_id, check in checks:
            try:
                result = check(cf, projects)
            except Exception as exc:  # noqa: BLE001
                result = {"error": str(exc)}
                gaps.append((source_id, GapReason.COLLECTOR_ERROR, f"Posture check failed: {exc}"))
                posture[source_id] = result
                continue
            gap = result.pop("_gap", None)
            posture[source_id] = result
            if gap:
                gaps.append((source_id, gap[0], gap[1]))

        files = [self.write_json(posture, "config.json")]
        self.write_meta(
            {
                "source": self.name,
                "checks": len(checks),
                "artifact_parameters": self.artifact_params(),
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=0,
            gaps=gaps,
            notes=f"Logging posture recorded for {len(checks)} source(s).",
        )

    def _check_vpc_flow_logs(self, cf, projects: list[str]) -> dict[str, Any]:
        subnets_total = 0
        subnets_with_flow = 0
        samples: list[str] = []
        for project_id in projects:
            try:
                subnets = cf.compute_subnetworks(project_id, max_items=MAX_SUBNETS)
            except (GcpAccessDenied, GcpServiceNotEnabled):
                continue
            for subnet in subnets:
                subnets_total += 1
                log_cfg = subnet.get("logConfig") or {}
                if log_cfg.get("enable"):
                    subnets_with_flow += 1
                    if len(samples) < 20:
                        name = subnet.get("name") or subnet.get("id") or ""
                        samples.append(f"{project_id}:{name}")
        out = {
            "subnets_total": subnets_total,
            "subnets_with_flow_logs": subnets_with_flow,
            "sample": samples,
        }
        if subnets_total == 0:
            out["_gap"] = (GapReason.NOT_PRESENT, "No subnetworks in scope.")
        elif subnets_with_flow == 0:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"VPC Flow Logs disabled on all {subnets_total} subnet(s).",
            )
        else:
            out["_gap"] = (
                GapReason.OUT_OF_SCOPE,
                f"Flow logs enabled on {subnets_with_flow}/{subnets_total} subnet(s). "
                f"{_PLANNED_COLLECTOR}",
            )
        return out

    def _check_firewall_logging(self, cf, projects: list[str]) -> dict[str, Any]:
        rules_total = 0
        rules_logged = 0
        samples: list[str] = []
        for project_id in projects:
            try:
                rules = cf.compute_firewalls(project_id, max_items=MAX_FIREWALLS)
            except (GcpAccessDenied, GcpServiceNotEnabled):
                continue
            for rule in rules:
                rules_total += 1
                log_cfg = rule.get("logConfig") or {}
                if log_cfg.get("enable"):
                    rules_logged += 1
                    if len(samples) < 20:
                        samples.append(f"{project_id}:{rule.get('name', '')}")
        out = {
            "firewall_rules_total": rules_total,
            "firewall_rules_with_logging": rules_logged,
            "sample": samples,
        }
        if rules_total == 0:
            out["_gap"] = (GapReason.NOT_PRESENT, "No VPC firewall rules in scope.")
        elif rules_logged == 0:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"Firewall rule logging disabled on all {rules_total} rule(s).",
            )
        else:
            out["_gap"] = (
                GapReason.OUT_OF_SCOPE,
                f"Logging enabled on {rules_logged}/{rules_total} firewall rule(s). "
                f"{_PLANNED_COLLECTOR}",
            )
        return out

    def _check_audit_sinks(self, cf, projects: list[str]) -> dict[str, Any]:
        sinks_total = 0
        audit_sinks = 0
        destinations: list[str] = []
        for project_id in projects:
            try:
                sinks = cf.list_log_sinks(project_id)
            except (GcpAccessDenied, GcpServiceNotEnabled):
                continue
            for sink in sinks:
                sinks_total += 1
                filt = str(sink.get("filter") or "")
                if "cloudaudit.googleapis.com" in filt or "logName:" in filt and "cloudaudit" in filt:
                    audit_sinks += 1
                    dest = str(sink.get("destination") or "")
                    if dest and len(destinations) < 20:
                        destinations.append(f"{project_id}:{dest}")
        out = {
            "sinks_total": sinks_total,
            "audit_log_sinks": audit_sinks,
            "destinations": destinations,
        }
        if sinks_total == 0:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                "No log export sinks configured — audit logs may only be in Cloud Logging.",
            )
        elif audit_sinks == 0:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"{sinks_total} sink(s) present but none export Cloud Audit logs.",
            )
        else:
            out["_gap"] = (
                GapReason.OUT_OF_SCOPE,
                f"{audit_sinks}/{sinks_total} sink(s) export Cloud Audit logs → "
                f"{', '.join(destinations[:3])}.",
            )
        return out
