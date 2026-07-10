"""Shared post-collection steps — seal evidence packages with live progress."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from ..lib.chain_of_custody.signing import sign_manifest
from ..lib.packaging.packager import PackageResult, seal_package
from .run_common import RunReporter

PIPELINE_PACKAGE = "package"
PIPELINE_INGEST = "ingest"


def finalize_and_seal_package(
    *,
    reporter: RunReporter,
    staging: Path,
    out_dir: Path,
    case_id: str,
    account_id: str,
    key_path: Path | None,
) -> PackageResult:
    """Sign the manifest and seal the staging tree into a compressed evidence package."""

    def _progress(msg: str) -> None:
        if hasattr(reporter, "step_event"):
            reporter.step_event(PIPELINE_PACKAGE, msg)
        else:
            reporter.event(PIPELINE_PACKAGE, msg)

    if hasattr(reporter, "start_step"):
        reporter.start_step(PIPELINE_PACKAGE, "Preparing evidence package…")

    sign_result = sign_manifest(staging / "manifest.json", key_path=key_path)
    _progress(f"Manifest signed ({sign_result.method})")

    package = seal_package(
        staging,
        out_dir,
        case_id,
        account_id,
        on_progress=_progress,
    )
    detail = f"{package.bytes:,} bytes · {package.compression}"
    if hasattr(reporter, "finish_step"):
        reporter.finish_step(PIPELINE_PACKAGE, success=True, detail=detail)
    return package


def ingest_progress_reporter(reporter: RunReporter) -> Callable[[str], None] | None:
    """Adapter for :func:`ventra_ingester.pipeline.ingest_package` progress lines."""

    if not hasattr(reporter, "step_event"):
        return None

    def _say(msg: str) -> None:
        reporter.step_event(PIPELINE_INGEST, msg)

    return _say
