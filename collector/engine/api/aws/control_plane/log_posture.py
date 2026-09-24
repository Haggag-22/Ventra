"""Logging-posture collector — presence detection for log sources Ventra does not yet pull.

For each IR cheat-sheet log source without a dedicated collector, this records whether it is
enabled in the account and where it ships (S3 bucket / CloudWatch group / Firehose). A
disabled log source is a forensic finding; an enabled one tells the responder exactly where
to collect manually. Each source is reported as a manifest gap named by its catalog id so
the console's Logs Coverage panel can show real per-source status instead of "unknown".

Checked: OpenSearch log publishing, DynamoDB Streams, Network Firewall logging.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled

MAX_ITEMS_PER_SERVICE = 200

# Shown in manifest gaps for sources Ventra detects but does not collect yet.
_PLANNED_COLLECTOR = "Coming soon — Ventra does not collect this source yet."


class LogPostureCollector(Collector):
    name = "log_posture"
    priority = 2
    description = (
        "Logging posture for sources without a Ventra log collector yet: "
        "OpenSearch, DynamoDB Streams, Network Firewall."
    )
    required_actions = (
        "logs:DescribeLogGroups",
        "es:ListDomainNames",
        "es:DescribeDomain",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "network-firewall:ListFirewalls",
        "network-firewall:DescribeLoggingConfiguration",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        posture: dict[str, Any] = {}

        checks = (
            ("opensearch", self._check_opensearch),
            ("dynamodb_streams", self._check_dynamodb_streams),
            ("network_firewall", self._check_network_firewall),
        )
        for source_id, check in checks:
            try:
                result = check(cf)
            except Exception as exc:  # noqa: BLE001 - one failed check must not sink the rest
                result = {"error": str(exc)}
                gaps.append((source_id, GapReason.COLLECTOR_ERROR, f"Posture check failed: {exc}"))
                posture[source_id] = result
                continue
            gap = result.pop("_gap", None)
            posture[source_id] = result
            if gap:
                gaps.append((source_id, gap[0], gap[1]))

        files = [self.write_json(posture, "config.json")]
        self.write_meta({"source": self.name, "checks": len(checks), "artifact_parameters": self.artifact_params()})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=0,
            gaps=gaps,
            notes=f"Logging posture recorded for {len(checks)} source(s).",
        )

    # -- per-source checks ----------------------------------------------------------------
    # Each returns a posture dict; "_gap" carries (reason, detail) for the manifest.

    def _check_opensearch(self, cf) -> dict[str, Any]:
        domains_total = 0
        domains_logged = 0
        destinations: list[str] = []
        for region in self.ctx.regions:
            try:
                names = cf.call("opensearch", region, "list_domain_names").get(
                    "DomainNames", []
                )
            except (AccessDenied, ServiceNotEnabled, ClientError):
                continue
            for entry in names[:MAX_ITEMS_PER_SERVICE]:
                domains_total += 1
                try:
                    status = cf.call(
                        "opensearch",
                        region,
                        "describe_domain",
                        DomainName=entry.get("DomainName", ""),
                    ).get("DomainStatus", {})
                except (AccessDenied, ServiceNotEnabled, ClientError):
                    continue
                opts = status.get("LogPublishingOptions") or {}
                enabled = [
                    f"{k}→{(v or {}).get('CloudWatchLogsLogGroupArn', '')}"
                    for k, v in opts.items()
                    if (v or {}).get("Enabled")
                ]
                if enabled:
                    domains_logged += 1
                    destinations.extend(enabled[:3])
        out = {
            "domains_total": domains_total,
            "domains_with_log_publishing": domains_logged,
            "destinations": destinations[:20],
        }
        if domains_total == 0:
            out["_gap"] = (GapReason.NOT_PRESENT, "No OpenSearch domains in scope.")
        elif domains_logged == 0:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"Log publishing disabled on all {domains_total} OpenSearch domain(s).",
            )
        else:
            out["_gap"] = (
                GapReason.OUT_OF_SCOPE,
                f"Log publishing enabled on {domains_logged}/{domains_total} domain(s). "
                f"{_PLANNED_COLLECTOR}",
            )
        return out

    def _check_dynamodb_streams(self, cf) -> dict[str, Any]:
        tables_total = 0
        tables_streaming = 0
        for region in self.ctx.regions:
            try:
                names = list(cf.paginate("dynamodb", region, "list_tables", "TableNames"))
            except (AccessDenied, ServiceNotEnabled, ClientError):
                continue
            for name in names[:MAX_ITEMS_PER_SERVICE]:
                tables_total += 1
                try:
                    table = cf.call("dynamodb", region, "describe_table", TableName=name).get(
                        "Table", {}
                    )
                except (AccessDenied, ServiceNotEnabled, ClientError):
                    continue
                if (table.get("StreamSpecification") or {}).get("StreamEnabled"):
                    tables_streaming += 1
        out = {"tables_total": tables_total, "tables_with_streams": tables_streaming}
        if tables_total == 0:
            out["_gap"] = (GapReason.NOT_PRESENT, "No DynamoDB tables in scope.")
        else:
            out["_gap"] = (
                GapReason.OUT_OF_SCOPE,
                f"Streams enabled on {tables_streaming}/{tables_total} table(s). Streams "
                "retain only 24h and cannot be read retrospectively — not collectible "
                "after the fact.",
            )
        return out

    def _check_network_firewall(self, cf) -> dict[str, Any]:
        firewalls_total = 0
        firewalls_logged = 0
        destinations: list[str] = []
        for region in self.ctx.regions:
            try:
                fws = list(
                    cf.paginate("network-firewall", region, "list_firewalls", "Firewalls")
                )
            except (AccessDenied, ServiceNotEnabled, ClientError):
                continue
            for fw in fws[:MAX_ITEMS_PER_SERVICE]:
                firewalls_total += 1
                try:
                    logging_config = cf.call(
                        "network-firewall",
                        region,
                        "describe_logging_configuration",
                        FirewallArn=fw.get("FirewallArn", ""),
                    ).get("LoggingConfiguration", {})
                except (AccessDenied, ServiceNotEnabled, ClientError):
                    continue
                configs = logging_config.get("LogDestinationConfigs") or []
                if configs:
                    firewalls_logged += 1
                    for c in configs:
                        dest = c.get("LogDestination") or {}
                        where = (
                            dest.get("bucketName")
                            or dest.get("logGroup")
                            or dest.get("deliveryStream")
                            or ""
                        )
                        destinations.append(f"{c.get('LogType', '')}→{where}")
        out = {
            "firewalls_total": firewalls_total,
            "firewalls_with_logging": firewalls_logged,
            "destinations": destinations[:20],
        }
        if firewalls_total == 0:
            out["_gap"] = (GapReason.NOT_PRESENT, "No Network Firewall in scope.")
        elif firewalls_logged == 0:
            out["_gap"] = (
                GapReason.LOGGING_NOT_CONFIGURED,
                f"Logging disabled on all {firewalls_total} firewall(s).",
            )
        else:
            out["_gap"] = (
                GapReason.OUT_OF_SCOPE,
                f"Logging enabled on {firewalls_logged}/{firewalls_total} firewall(s) → "
                f"{', '.join(destinations[:3])}. {_PLANNED_COLLECTOR}",
            )
        return out
