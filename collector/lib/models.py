"""Core data models shared across all collectors.

These mirror the Ventra manifest schema (``schemas/manifest.schema.json``). Keeping them as
plain dataclasses keeps the collector dependency-light enough to run in a cloud shell.
"""

from __future__ import annotations

import dataclasses
import enum
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    """RFC 3339 UTC timestamp with second precision and a trailing Z."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class SourceStatus(enum.StrEnum):
    COLLECTED = "collected"
    EMPTY = "empty"
    PARTIAL = "partial"
    ERRORED = "errored"
    SKIPPED = "skipped"


class GapReason(enum.StrEnum):
    SERVICE_NOT_ENABLED = "service_not_enabled"
    LOGGING_NOT_CONFIGURED = "logging_not_configured"
    ACCESS_DENIED = "access_denied"
    REGION_OPTED_OUT = "region_opted_out"
    NOT_PRESENT = "not_present"
    COLLECTOR_ERROR = "collector_error"
    LOG_INTEGRITY_FAILED = "log_integrity_failed"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass
class WrittenFile:
    """A single file a collector wrote into the staging area."""

    path: str  # path within the archive, e.g. sources/cloudtrail/events.jsonl.zst
    sha256: str
    bytes: int
    record_count: int | None = None


@dataclass
class SourceResult:
    """What a collector returns after it runs.

    A collector may produce multiple files (events, config, meta) but is reported as a single
    logical source in the manifest. ``status`` and any ``gaps`` describe collection outcome —
    a gap is evidence, not a failure to hide.
    """

    name: str
    status: SourceStatus
    files: list[WrittenFile] = field(default_factory=list)
    record_count: int | None = None
    gaps: list[tuple[str, GapReason, str]] = field(default_factory=list)
    notes: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def primary_file(self) -> WrittenFile | None:
        return self.files[0] if self.files else None


@dataclass
class TimeWindow:
    since: datetime | None = None
    until: datetime | None = None

    @property
    def mode(self) -> str:
        return "window" if (self.since or self.until) else "full_available"

    def to_manifest(self) -> dict[str, Any]:
        return {
            "since": self.since.strftime("%Y-%m-%dT%H:%M:%SZ") if self.since else None,
            "until": self.until.strftime("%Y-%m-%dT%H:%M:%SZ") if self.until else None,
            "mode": self.mode,
        }


@dataclass
class Operator:
    principal_arn: str
    user_id: str = ""
    source_ip: str = ""

    def to_manifest(self) -> dict[str, Any]:
        out: dict[str, Any] = {"principal_arn": self.principal_arn}
        if self.user_id:
            out["user_id"] = self.user_id
        if self.source_ip:
            out["source_ip"] = self.source_ip
        return out


@dataclass
class ArtifactRef:
    """Provenance for one artifact collected in a run — recorded in the manifest.

    ``collector`` is the registry key the engine ran; ``name`` and ``version`` come from the
    artifact YAML (e.g. ``GCP.ManagementPlane.CloudAuditAdmin`` / ``1.0.0``). ``parameters``
    captures any per-artifact tuning carried in from an acquisition spec.
    """

    name: str
    version: str
    collector: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_manifest(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "collector": self.collector,
        }
        if self.parameters:
            out["parameters"] = self.parameters
        return out


@dataclass
class Manifest:
    """Assembles into the JSON validated by schemas/manifest.schema.json."""

    schema_version: str
    tool_version: str
    case_id: str
    cloud: str
    account_id: str
    regions: list[str]
    operator: Operator
    started_at: str
    completed_at: str
    profile_name: str
    host_environment: str
    tool_commit: str = ""
    engagement_id: str = ""
    account_alias: str = ""
    org_id: str = ""
    partition: str = ""
    time_window: TimeWindow = field(default_factory=TimeWindow)
    profile_overrides: list[str] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[ArtifactRef] = field(default_factory=list)
    host_os: str = ""
    host_runtime: str = ""

    def add_source_result(self, result: SourceResult) -> None:
        for wf in result.files:
            self.sources.append(
                {
                    "name": result.name,
                    "path": wf.path,
                    "record_count": wf.record_count
                    if wf.record_count is not None
                    else result.record_count,
                    "bytes": wf.bytes,
                    "sha256": wf.sha256,
                    "status": result.status.value,
                    "notes": result.notes,
                }
            )
        if not result.files and result.status != SourceStatus.COLLECTED:
            # A source that produced no file but ran (e.g. empty / skipped) still gets an entry
            # so the analyst sees it was attempted.
            self.sources.append(
                {
                    "name": result.name,
                    "path": "",
                    "record_count": result.record_count,
                    "bytes": 0,
                    "sha256": "0" * 64,
                    "status": result.status.value,
                    "notes": result.notes,
                }
            )
        for name, reason, detail in result.gaps:
            self.gaps.append({"name": name, "reason": reason.value, "detail": detail})

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "case_id": self.case_id,
            "cloud": self.cloud,
            "account_id": self.account_id,
            "regions": self.regions,
            "operator": self.operator.to_manifest(),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "time_window": self.time_window.to_manifest(),
            "profile": {"name": self.profile_name, "overrides": self.profile_overrides},
            "sources": self.sources,
            "gaps": self.gaps,
            "host": {
                "environment": self.host_environment,
                "os": self.host_os,
                "runtime": self.host_runtime,
            },
        }
        if self.artifacts:
            out["artifacts"] = [a.to_manifest() for a in self.artifacts]
        for opt in ("tool_commit", "engagement_id", "account_alias", "org_id", "partition"):
            val = getattr(self, opt)
            if val:
                out[opt] = val
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)

    def write(self, path: Path) -> None:
        path.write_text(self.to_json(), encoding="utf-8")


@dataclass
class UalCollectOptions:
    """Optional filters for M365 Unified Audit Log collectors (Management API + Search cmdlet)."""

    users: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    record_types: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    target_events_per_window: int = 3000
    audit_data_only: bool = False


@dataclass
class AzureAuthOptions:
    """Service-principal credentials for host-side Azure collection (CLI flags or env vars)."""

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    client_certificate_path: str = ""
    client_certificate_password: str = ""


@dataclass
class CollectionContext:
    """Everything a collector needs to do its job, passed by the runner.

    ``session_factory`` returns a boto3 client for a service/region without the collector
    needing to know how credentials were obtained. ``staging`` is where collectors write
    their files; the packager seals it afterwards.
    """

    cloud: str
    account_id: str
    regions: list[str]
    time_window: TimeWindow
    staging: Path
    case_id: str
    # Azure/M365 scope. ``account_id`` holds the tenant id for those clouds; ``subscription_ids``
    # is the set of in-scope subscriptions an ARM-scoped collector iterates. Empty for AWS.
    tenant_id: str = ""
    subscription_ids: list[str] = field(default_factory=list)
    # GCP scope — in-scope project ids a logging/IAM collector iterates.
    project_ids: list[str] = field(default_factory=list)
    # Per-source record cap. None = collect all records in since/until; a positive int stops
    # early per source (optional triage); 0 or negative also means unlimited within the window.
    max_records_per_source: int | None = None
    # Per-artifact parameter values from the acquisition spec, keyed by collector name. A
    # collector reads its own filters here (e.g. a per-artifact ``since``) via ``artifact_params``.
    artifact_parameters: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Injected by the runner; typed loosely to keep this module cloud-agnostic.
    client_factory: Any = None
    logger: Any = None
    ual: UalCollectOptions = field(default_factory=UalCollectOptions)

    def source_dir(self, name: str) -> Path:
        d = self.staging / "sources" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def error_log(self, name: str) -> Path:
        d = self.staging / "errors"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{name}.log"


def asdict_clean(obj: Any) -> Any:
    """dataclasses.asdict that drops Nones for compact manifests."""
    if dataclasses.is_dataclass(obj):
        return {k: asdict_clean(v) for k, v in dataclasses.asdict(obj).items() if v is not None}
    return obj
