"""Orchestrates an AWS collection run end-to-end.

Runs every collector in the config list, builds the shared context, isolates failures so one
error never aborts the run, assembles + signs the manifest, and seals the package.
"""

from __future__ import annotations

import json
import platform
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from collector import __version__
from collector.clouds.aws.client_factory import AwsClientFactory
from collector.engine.acquisition import artifact_refs_for_collectors
from collector.engine.registry import AWS_REGISTRY
from collector.engine.run_common import RunReporter, parse_window
from collector.lib.auth import manifest_profile_overrides
from collector.lib.base import Collector
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

__all__ = ["AwsRunConfig", "RunReporter", "parse_window", "run_aws_collection"]

SCHEMA_VERSION = "1.0.0"


@dataclass
class AwsRunConfig:
    case_id: str
    collectors: list[str]
    regions: list[str] | None
    time_window: TimeWindow
    out_dir: Path
    engagement_id: str = ""
    key_path: Path | None = None
    reporter: RunReporter | None = None
    aws_profile: str = ""
    artifact_refs: list[ArtifactRef] = field(default_factory=list)
    max_records_per_source: int | None = None
    artifact_parameters: dict[str, dict] = field(default_factory=dict)
    plan_label: str = ""
    artifact_labels: dict[str, str] = field(default_factory=dict)
    artifact_severities: dict[str, str] = field(default_factory=dict)


def _detect_environment() -> str:
    import os

    if os.environ.get("AWS_EXECUTION_ENV", "").lower().startswith("cloudshell"):
        return "cloudshell"
    if os.environ.get("AWS_EXECUTION_ENV"):
        return "ec2"
    if os.path.exists("/sys/hypervisor/uuid") or os.environ.get("ECS_CONTAINER_METADATA_URI"):
        return "ec2"
    return "local"


def run_aws_collection(cfg: AwsRunConfig, *, factory: AwsClientFactory | None = None) -> PackageResult:
    started = utcnow_iso()
    if factory is None and cfg.aws_profile:
        import boto3

        factory = AwsClientFactory(boto3.Session(profile_name=cfg.aws_profile))
    cf = factory or AwsClientFactory()
    identity = cf.caller_identity()
    regions = cfg.regions or cf.enabled_regions()

    reporter = cfg.reporter or RunReporter()
    reporter.begin_run(
        identity.account_id,
        regions,
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
            cloud="aws",
            account_id=identity.account_id,
            regions=regions,
            time_window=cfg.time_window,
            staging=staging,
            case_id=cfg.case_id,
            client_factory=cf,
            logger=reporter,
            max_records_per_source=cfg.max_records_per_source,
            artifact_parameters=cfg.artifact_parameters,
        )

        manifest = Manifest(
            schema_version=SCHEMA_VERSION,
            tool_version=__version__,
            case_id=cfg.case_id,
            engagement_id=cfg.engagement_id,
            cloud="aws",
            account_id=identity.account_id,
            partition=identity.partition,
            regions=regions,
            operator=Operator(principal_arn=identity.arn, user_id=identity.user_id),
            started_at=started,
            completed_at="",  # filled below
            time_window=cfg.time_window,
            profile_name="all",
            profile_overrides=manifest_profile_overrides(aws_profile=cfg.aws_profile),
            host_environment=_detect_environment(),
            host_os=platform.platform(),
            host_runtime=f"python {platform.python_version()}",
        )
        manifest.artifacts = cfg.artifact_refs or artifact_refs_for_collectors("aws", cfg.collectors)

        collection_log: list[dict] = []
        for name in cfg.collectors:
            cls = AWS_REGISTRY.get(name)
            if cls is None:
                manifest.add_source_result(
                    SourceResult(
                        name=name,
                        status=SourceStatus.SKIPPED,
                        gaps=[(name, GapReason.OUT_OF_SCOPE, "Unknown collector for AWS.")],
                        notes="Unknown collector name.",
                    )
                )
                continue
            reporter.start(name)
            result = _run_one(cls, ctx)
            reporter.finish(name, result)
            manifest.add_source_result(result)
            collection_log.append(
                {
                    "ts": utcnow_iso(),
                    "collector": name,
                    "status": result.status.value,
                    "records": result.record_count,
                    "gaps": [g[0] for g in result.gaps],
                    "errors": result.errors,
                }
            )
            if result.errors:
                ctx.error_log(name).write_text("\n".join(result.errors), encoding="utf-8")

        manifest.account_alias = _account_alias(staging)
        manifest.completed_at = utcnow_iso()

        _write_collection_log(staging, collection_log)
        manifest_path = staging / "manifest.json"
        manifest.write(manifest_path)
        sign_result = sign_manifest(manifest_path, cfg.key_path)
        reporter.event("_seal", f"manifest signed via {sign_result.method}")

        package = seal_package(
            staging=staging,
            out_dir=cfg.out_dir,
            case_id=cfg.case_id,
            account_id=identity.account_id,
        )
        return package


def _run_one(cls: type[Collector], ctx: CollectionContext) -> SourceResult:
    """Run a single collector, converting any unexpected exception into an errored result."""
    try:
        return cls(ctx).collect()
    except Exception as exc:  # noqa: BLE001 - isolation is intentional
        return SourceResult(
            name=cls.name,
            status=SourceStatus.ERRORED,
            gaps=[(cls.name, GapReason.COLLECTOR_ERROR, str(exc))],
            errors=[traceback.format_exc()],
            notes=f"Collector raised: {exc}",
        )


def _account_alias(staging: Path) -> str:
    snap = staging / "sources" / "account" / "snapshot.json"
    if snap.exists():
        try:
            return json.loads(snap.read_text()).get("account_alias", "")
        except Exception:
            return ""
    return ""


def _write_collection_log(staging: Path, entries: list[dict]) -> None:
    path = staging / "collection.log"
    with path.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e, default=str) + "\n")
