"""Orchestrates an Azure collection run."""

from __future__ import annotations

import platform
import tempfile
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ... import __version__
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
from .registry import AZURE_REGISTRY

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


@dataclass
class RunReporter:
    events: list[tuple[str, str]] = field(default_factory=list)

    def begin_run(
        self,
        account_id: str,
        regions: list[str],
        case_id: str = "",
        collectors: list[str] | None = None,
    ) -> None:
        pass

    def start(self, name: str) -> None:
        self._emit(name, "running")

    def finish(self, name: str, result: SourceResult) -> None:
        self._emit(name, result.status.value)

    def event(self, name: str, msg: str) -> None:
        self.events.append((name, msg))

    def _emit(self, name: str, status: str) -> None:
        self.events.append((name, status))


def _detect_environment() -> str:
    import os

    if os.environ.get("AZUREPS_HOST_ENVIRONMENT", "").lower().find("cloudshell") >= 0:
        return "cloudshell"
    if os.environ.get("AZURE_CLOUD_SHELL"):
        return "cloudshell"
    return "local"


def run_azure_collection(
    cfg: AzureRunConfig,
    *,
    factory: AzureClientFactory | None = None,
) -> PackageResult:
    started = utcnow_iso()
    cf = factory or AzureClientFactory(subscription_id=cfg.subscription_id)
    identity = cf.identity()
    regions = cfg.regions or cf.enabled_regions()

    reporter = cfg.reporter or RunReporter()
    reporter.begin_run(identity.subscription_id, regions, cfg.case_id, cfg.collectors)

    with tempfile.TemporaryDirectory(prefix="ventra-azure-") as tmp:
        staging = Path(tmp)
        (staging / "sources").mkdir(parents=True, exist_ok=True)

        ctx = CollectionContext(
            cloud="azure",
            account_id=identity.subscription_id,
            regions=regions,
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
            account_id=identity.subscription_id,
            partition="azure",
            regions=regions,
            operator=Operator(
                principal_arn=identity.principal_name or identity.principal_id,
                user_id=identity.principal_id,
            ),
            started_at=started,
            completed_at="",
            time_window=cfg.time_window,
            profile_name="all",
            profile_overrides=[],
            host_environment=_detect_environment(),
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

        manifest.account_alias = _subscription_display(staging)
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
            account_id=identity.subscription_id,
        )


def _run_one(cls: type[Collector], ctx: CollectionContext) -> SourceResult:
    try:
        return cls(ctx).collect()
    except Exception as exc:  # noqa: BLE001
        return SourceResult(
            name=cls.name,
            status=SourceStatus.ERRORED,
            gaps=[(cls.name, GapReason.COLLECTOR_ERROR, str(exc))],
            errors=[traceback.format_exc()],
            notes=f"Collector raised: {exc}",
        )


def _subscription_display(staging: Path) -> str:
    import json

    snap = staging / "sources" / "subscription" / "snapshot.json"
    if snap.exists():
        try:
            data = json.loads(snap.read_text())
            return data.get("display_name") or data.get("subscription_id", "")
        except Exception:
            return ""
    return ""


def parse_window(since: str | None, until: str | None) -> TimeWindow:
    def _p(val: str | None) -> datetime | None:
        if not val:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
            try:
                return datetime.strptime(val, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        raise ValueError(f"Unrecognized date: {val!r}. Use YYYY-MM-DD or RFC3339.")

    return TimeWindow(since=_p(since), until=_p(until))
