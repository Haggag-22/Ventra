"""Shared collection matrix state — used by the CLI Rich renderer and ApiReporter."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from ..lib.models import GapReason, SourceResult, SourceStatus

# Per-source severity tiers (mirrors collector/cli.py).
_SEVERITY: dict[str, str] = {
    "account": "Low",
    "cloudtrail": "High",
    "iam": "High",
    "vpc_flow": "High",
    "waf": "Medium",
    "guardduty": "High",
    "macie": "Medium",
    "detective": "Medium",
    "config": "High",
    "securityhub": "High",
    "kms": "Medium",
    "secrets": "Medium",
    "ec2": "Medium",
    "s3": "Medium",
    "lambda": "Low",
    "inspector2": "Medium",
    "elb_alb": "Medium",
    "cloudfront": "Medium",
    "s3_access": "Medium",
    "route53_resolver": "Medium",
    "eks_audit": "Medium",
    "log_posture": "Low",
    "subscription": "Low",
    "activity_log": "High",
    "entra_signin": "High",
    "entra_audit": "High",
    "rbac": "High",
    "nsg_flow": "High",
    "defender": "High",
    "vnet_flow": "High",
    "azure_firewall": "Medium",
    "app_gateway": "Medium",
    "front_door": "Medium",
    "dns": "Medium",
    "storage_access": "Medium",
    "bigquery_audit": "High",
    "cloud_sql": "High",
    "secret_manager": "High",
    "key_vault": "Medium",
    "aks_audit": "Medium",
    "entra_directory": "High",
    "resource_graph": "Low",
    "diag_posture": "Low",
    "log_analytics": "Medium",
    "unified_audit": "High",
    "unified_audit_search": "High",
    "oauth_consent": "High",
    "cloud_audit_admin": "High",
    "cloud_audit_system": "High",
    "cloud_audit_data": "High",
    "login_events": "High",
    "firewall_logs": "Medium",
    "load_balancer": "Medium",
    "cloud_cdn": "Medium",
    "api_gateway": "Medium",
    "vm_logs": "Medium",
    "cloud_functions": "Medium",
    "scc_findings": "High",
    "cloud_monitoring": "Medium",
    "iam_policy": "High",
    "project": "Low",
}

_ARTIFACT_SEV = {"critical": "High", "extended": "Medium", "optional": "Low"}

# Public aliases used by run_launcher.
ARTIFACT_SEVERITY = _ARTIFACT_SEV
DEFAULT_SEVERITY = _SEVERITY


def classify(status: SourceStatus, severity: str) -> str:
    """Map a collector outcome to PASS or FAIL for the live matrix."""
    del severity
    if status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL):
        return "PASS"
    return "FAIL"


@dataclass
class CollectorRow:
    name: str
    status: str = "pending"
    severity: str = "Medium"
    records: int | None = None
    elapsed_ms: float | None = None
    detail: str = "queued"
    live_msg: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MatrixState:
    """Mutable matrix table state shared between terminal and HTTP reporters."""

    account_id: str = ""
    masked_account: str = "????"
    case_id: str = ""
    regions: list[str] = field(default_factory=list)
    plan_label: str = ""
    order: list[str] = field(default_factory=list)
    rows: dict[str, CollectorRow] = field(default_factory=dict)
    finished_csv_rows: list[dict[str, Any]] = field(default_factory=list)
    rate_limited: list[str] = field(default_factory=list)
    artifact_labels: dict[str, str] = field(default_factory=dict)
    artifact_severities: dict[str, str] = field(default_factory=dict)
    _started_at: dict[str, float] = field(default_factory=dict, repr=False)
    registry_get: Callable[[str], Any] | None = None
    severity_resolver: Callable[[str], str] | None = None

    def severity_for(self, name: str) -> str:
        if name in self.artifact_severities:
            return self.artifact_severities[name]
        if self.severity_resolver is not None:
            return self.severity_resolver(name)
        cls = self.registry_get(name) if self.registry_get else None
        priority = getattr(cls, "priority", 2) if cls else 2
        return _SEVERITY.get(name, "High" if priority == 1 else "Medium")

    def begin_run(
        self,
        account_id: str,
        regions: list[str],
        case_id: str = "",
        collectors: list[str] | None = None,
        *,
        plan_label: str = "",
        artifact_labels: dict[str, str] | None = None,
        artifact_severities: dict[str, str] | None = None,
    ) -> None:
        self.account_id = account_id or ""
        self.masked_account = (account_id[:4] + "***") if account_id else "????"
        self.case_id = case_id or ""
        self.regions = list(regions or [])
        self.plan_label = plan_label
        self.artifact_labels = dict(artifact_labels or {})
        self.artifact_severities = dict(artifact_severities or {})
        self.order = list(collectors or [])
        self.rows = {}
        self.finished_csv_rows = []
        self.rate_limited = []
        self._started_at = {}
        for name in self.order:
            self.rows[name] = CollectorRow(
                name=name,
                status="pending",
                severity=self.severity_for(name),
                detail="queued",
            )

    def start(self, name: str) -> None:
        row = self.rows.get(name)
        if row is None:
            return
        row.status = "running"
        row.live_msg = "collecting…"
        self._started_at[name] = time.monotonic()

    def event(self, name: str, msg: str) -> None:
        row = self.rows.get(name)
        if row is not None and row.status == "running":
            row.live_msg = msg

    def finish(
        self,
        name: str,
        result: SourceResult,
        *,
        description_for: Callable[[str], str] | None = None,
    ) -> None:
        row = self.rows.get(name)
        severity = row.severity if row else self.severity_for(name)
        label = classify(result.status, severity)
        if any(g[1] == GapReason.RATE_LIMITED for g in (result.gaps or [])):
            self.rate_limited.append(name)

        count = result.record_count
        if result.status != SourceStatus.COLLECTED and result.gaps:
            desc = result.gaps[0][2] or result.notes
        else:
            cls = self.registry_get(name) if self.registry_get else None
            desc = result.notes or (getattr(cls, "description", "") if cls else "")

        elapsed = None
        started = self._started_at.get(name)
        if started is not None:
            elapsed = time.monotonic() - started

        if row is not None:
            row.status = "pass" if label == "PASS" else "fail"
            row.records = count if isinstance(count, int) else None
            row.detail = desc or ""
            row.elapsed_ms = round(elapsed * 1000, 1) if elapsed is not None else None
            row.live_msg = ""

        tag = f"{count:,}" if isinstance(count, int) else "-"
        self.finished_csv_rows.append(
            {
                "label": label,
                "scope": "global",
                "check": name.upper(),
                "severity": severity,
                "tag": tag,
                "elapsed": f"{elapsed:.2f}" if elapsed is not None else "",
                "desc": desc or "",
            }
        )

    def complete_count(self) -> tuple[int, int]:
        done = sum(1 for n in self.order if self.rows[n].status in ("pass", "fail"))
        return done, len(self.order)

    def progress(self) -> tuple[int, int]:
        return self.complete_count()

    def snapshot_rows(self) -> list[CollectorRow]:
        return [self.rows[n] for n in self.order if n in self.rows]

    def rate_limited_collectors(self) -> list[str]:
        return list(self.rate_limited)

    def snapshot(self) -> dict[str, Any]:
        done, total = self.complete_count()
        return {
            "account_id": self.account_id,
            "masked_account": self.masked_account,
            "case_id": self.case_id,
            "regions": self.regions,
            "plan_label": self.plan_label,
            "complete": done,
            "total": total,
            "collectors": [self.rows[n].to_dict() for n in self.order if n in self.rows],
        }

    def coverage_gaps(self) -> list[dict[str, str]]:
        rank = {"High": 0, "Medium": 1, "Low": 2}
        gaps = [
            {"collector": name, "severity": self.rows[name].severity, "detail": self.rows[name].detail}
            for name in self.order
            if self.rows[name].status == "fail"
        ]
        gaps.sort(key=lambda g: rank.get(g["severity"], 3))
        return gaps

    def collectors_report(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "status": self.rows[name].status,
                "severity": self.rows[name].severity,
                "records": self.rows[name].records,
                "elapsed_seconds": (
                    round(self.rows[name].elapsed_ms / 1000, 3)
                    if self.rows[name].elapsed_ms is not None
                    else None
                ),
                "detail": self.rows[name].detail,
            }
            for name in self.order
            if name in self.rows
        ]

    @staticmethod
    def artifact_severity(raw: str) -> str:
        return _ARTIFACT_SEV.get(raw, "Medium")
