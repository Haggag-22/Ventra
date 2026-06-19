"""Orchestrates a GCP collection run end-to-end."""

from __future__ import annotations

import json
import platform
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from collector import __version__
from collector.clouds.gcp.client_factory import GcpClientFactory
from collector.engine.acquisition import artifact_refs_for_collectors
from collector.engine.registry import GCP_REGISTRY
from collector.engine.run_common import RunReporter, parse_window
from collector.lib.chain_of_custody.signing import sign_manifest
from collector.lib.models import (
    ArtifactRef,
    CollectionContext,
    GapReason,
    Manifest,
    Operator,
    SourceResult,
    SourceStatus,
    TimeWindow,
    utcnow_iso,
)
from collector.lib.packaging.packager import PackageResult, seal_package

__all__ = ["GcpRunConfig", "run_gcp_collection", "parse_window"]

SCHEMA_VERSION = "1.0.0"


@dataclass
class GcpRunConfig:
    case_id: str
    collectors: list[str]
    regions: list[str] | None
    project_id: str | None
    time_window: TimeWindow
    out_dir: Path
    engagement_id: str = ""
    key_path: Path | None = None
    reporter: RunReporter | None = None
    credentials_path: str | None = None
    artifact_refs: list[ArtifactRef] = field(default_factory=list)
    max_records_per_source: int | None = None
    artifact_parameters: dict[str, dict] = field(default_factory=dict)
    plan_label: str = ""
    artifact_labels: dict[str, str] = field(default_factory=dict)
    artifact_severities: dict[str, str] = field(default_factory=dict)


def run_gcp_collection(
    cfg: GcpRunConfig, *, factory: GcpClientFactory | None = None
) -> PackageResult:
    started = utcnow_iso()
    cf = factory or GcpClientFactory(
        project_id=cfg.project_id,
        credentials_path=cfg.credentials_path,
    )
    identity = cf.caller_identity()
    explicit = None
    if cfg.project_id:
        explicit = [p.strip() for p in cfg.project_id.split(",") if p.strip()]
    projects = cf.projects(explicit=explicit)

    reporter = cfg.reporter or RunReporter()
    reporter.begin_run(
        identity.project_id or identity.organization_id,
        projects,
        cfg.case_id,
        cfg.collectors,
        plan_label=cfg.plan_label,
        artifact_labels=cfg.artifact_labels,
        artifact_severities=cfg.artifact_severities,
    )

    with tempfile.TemporaryDirectory(prefix="ventra-stage-") as tmp:
        staging = Path(tmp)
        (staging / "sources").mkdir(parents=True, exist_ok=True)

        ctx = CollectionContext(
            cloud="gcp",
            account_id=identity.organization_id or identity.project_id,
            regions=cfg.regions or [],
            time_window=cfg.time_window,
            staging=staging,
            case_id=cfg.case_id,
            client_factory=cf,
            logger=reporter,
            max_records_per_source=cfg.max_records_per_source,
            artifact_parameters=cfg.artifact_parameters,
        )
        ctx.project_ids = projects

        manifest = Manifest(
            schema_version=SCHEMA_VERSION,
            tool_version=__version__,
            case_id=cfg.case_id,
            engagement_id=cfg.engagement_id,
            cloud="gcp",
            account_id=identity.organization_id or identity.project_id,
            partition="gcp",
            org_id=identity.organization_id,
            regions=cfg.regions or [],
            operator=Operator(
                principal_arn=f"gcp-sa:{identity.principal}",
                user_id=identity.project_id,
            ),
            started_at=started,
            completed_at="",
            time_window=cfg.time_window,
            profile_name="all",
            profile_overrides=[],
            account_alias=identity.project_id,
            host_environment="local",
            host_os=platform.platform(),
            host_runtime=f"python {platform.python_version()}",
        )
        manifest.artifacts = cfg.artifact_refs or artifact_refs_for_collectors("gcp", cfg.collectors)

        collection_log: list[dict] = []
        for name in cfg.collectors:
            cls = GCP_REGISTRY.get(name)
            if cls is None:
                manifest.add_source_result(
                    SourceResult(
                        name=name,
                        status=SourceStatus.SKIPPED,
                        notes=f"Unknown collector {name!r}.",
                    )
                )
                continue
            reporter.start(name)
            result = _run_one(cls, ctx, collection_log)
            reporter.finish(name, result)
            manifest.add_source_result(result)

        manifest.completed_at = utcnow_iso()
        manifest.write(staging / "manifest.json")
        (staging / "collection.log").write_text(json.dumps(collection_log, indent=2), encoding="utf-8")

        sign_manifest(staging / "manifest.json", key_path=cfg.key_path)
        return seal_package(staging, cfg.out_dir, cfg.case_id)


def _run_one(cls: type, ctx: CollectionContext, log: list[dict]) -> SourceResult:
    name = cls.name
    try:
        collector = cls(ctx)
        result = collector.collect()
        log.append({"collector": name, "status": result.status.value, "records": result.record_count})
        return result
    except Exception as exc:  # noqa: BLE001
        tb = traceback.format_exc()
        ctx.error_log(name).write_text(tb, encoding="utf-8")
        log.append({"collector": name, "status": "errored", "error": str(exc)})
        return SourceResult(
            name=name,
            status=SourceStatus.ERRORED,
            gaps=[(name, GapReason.COLLECTOR_ERROR, str(exc))],
            notes=str(exc),
            errors=[tb],
        )
