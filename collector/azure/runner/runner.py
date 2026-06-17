"""Orchestrates an Azure collection run end-to-end.

Mirrors ``run_aws_collection``: resolve tenant identity + in-scope subscriptions, build the
shared context, run every registered collector with per-collector failure isolation, assemble
+ sign the manifest, and seal the package. The evidence-package format, signing, and unified
schema are shared with AWS unchanged — only acquisition differs.
"""

from __future__ import annotations

import json
import platform
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path

from ... import __version__
from ...aws.runner.runner import RunReporter, parse_window  # shared, cloud-agnostic
from ...lib.base import Collector
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
from ..client_factory import AzureClientFactory
from ..registry import AZURE_REGISTRY

__all__ = ["AzureRunConfig", "run_azure_collection", "parse_window"]

SCHEMA_VERSION = "1.0.0"


@dataclass
class AzureRunConfig:
    case_id: str
    collectors: list[str]
    regions: list[str] | None
    subscription_id: str | None
    time_window: TimeWindow
    out_dir: Path
    engagement_id: str = ""
    key_path: Path | None = None
    reporter: RunReporter | None = None


def run_azure_collection(
    cfg: AzureRunConfig, *, factory: AzureClientFactory | None = None
) -> PackageResult:
    started = utcnow_iso()
    cf = factory or AzureClientFactory(subscription_id=cfg.subscription_id)
    identity = cf.caller_identity()
    subscriptions = cf.subscriptions()

    reporter = cfg.reporter or RunReporter()
    reporter.begin_run(identity.tenant_id, subscriptions, cfg.case_id, cfg.collectors)

    with tempfile.TemporaryDirectory(prefix="ventra-stage-") as tmp:
        staging = Path(tmp)
        (staging / "sources").mkdir(parents=True, exist_ok=True)

        ctx = CollectionContext(
            cloud="azure",
            account_id=identity.tenant_id,
            tenant_id=identity.tenant_id,
            subscription_ids=subscriptions,
            regions=cfg.regions or [],
            time_window=cfg.time_window,
            staging=staging,
            case_id=cfg.case_id,
            client_factory=cf,
            logger=reporter,
        )

        manifest = Manifest(
            schema_version=SCHEMA_VERSION,
            tool_version=__version__,
            case_id=cfg.case_id,
            engagement_id=cfg.engagement_id,
            cloud="azure",
            account_id=identity.tenant_id,
            partition="azure",
            regions=cfg.regions or [],
            operator=Operator(
                principal_arn=f"azure-sp:{identity.principal}", user_id=identity.tenant_id
            ),
            started_at=started,
            completed_at="",
            time_window=cfg.time_window,
            profile_name="all",
            profile_overrides=[],
            account_alias=identity.tenant_name,
            host_environment="local",
            host_os=platform.platform(),
            host_runtime=f"python {platform.python_version()}",
        )

        collection_log: list[dict] = []
        for name in cfg.collectors:
            cls = AZURE_REGISTRY.get(name)
            if cls is None:
                manifest.add_source_result(
                    SourceResult(
                        name=name,
                        status=SourceStatus.SKIPPED,
                        gaps=[(name, GapReason.OUT_OF_SCOPE, "Unknown collector for Azure.")],
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

        manifest.completed_at = utcnow_iso()
        _write_collection_log(staging, collection_log)
        manifest_path = staging / "manifest.json"
        manifest.write(manifest_path)
        sign_result = sign_manifest(manifest_path, cfg.key_path)
        reporter.event("_seal", f"manifest signed via {sign_result.method}")

        return seal_package(
            staging=staging,
            out_dir=cfg.out_dir,
            case_id=cfg.case_id,
            account_id=identity.tenant_id,
        )


def _run_one(cls: type[Collector], ctx: CollectionContext) -> SourceResult:
    """Run a single collector; convert any unexpected exception into an errored result."""
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


def _write_collection_log(staging: Path, entries: list[dict]) -> None:
    path = staging / "collection.log"
    with path.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e, default=str) + "\n")
