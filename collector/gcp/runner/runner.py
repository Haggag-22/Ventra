"""Orchestrates a GCP collection run end-to-end."""

from __future__ import annotations

import json
import platform
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path

from ... import __version__
from ...aws.runner.runner import RunReporter, parse_window
from ...lib.chain_of_custody.signing import sign_manifest
from ...lib.models import (
    CollectionContext,
    GapReason,
    Manifest,
    Operator,
    SourceResult,
    SourceStatus,
    TimeWindow,
    utcnow_iso,
)
from ...lib.packaging.packager import PackageResult, seal_package
from collector.clouds.gcp.client_factory import GcpClientFactory
from collector.engine.registry import GCP_REGISTRY

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


def run_gcp_collection(
    cfg: GcpRunConfig, *, factory: GcpClientFactory | None = None
) -> PackageResult:
    started = utcnow_iso()
    cf = factory or GcpClientFactory(
        project_id=cfg.project_id,
        credentials_path=cfg.credentials_path,
    )
    identity = cf.caller_identity()
    explicit = [cfg.project_id] if cfg.project_id else None
    projects = cf.projects(explicit=explicit)

    reporter = cfg.reporter or RunReporter()
    reporter.begin_run(identity.project_id or identity.organization_id, projects, cfg.case_id, cfg.collectors)

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
            result = _run_one(cls, ctx, collection_log)
            manifest.add_source_result(result)
            if reporter:
                reporter.source_done(name, result)

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
