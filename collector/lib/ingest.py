"""Optional post-collect ingest into the analyst case store."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any


def default_case_store() -> Path:
    return Path(os.environ.get("VENTRA_CASE_STORE", "./cases"))


def running_in_cloudshell() -> bool:
    """True when running inside AWS CloudShell.

    CloudShell is acquisition-only — the case store and console live on the IR workstation —
    so the collector seals the package there and skips ingest by default.
    """
    return os.environ.get("AWS_EXECUTION_ENV", "").lower().startswith("cloudshell")


def ingest_after_collect(
    package_path: Path,
    case_store: Path,
    *,
    reporter: Callable[[str], Any] | None = None,
) -> int:
    """Load a sealed package into ``case_store``. Returns process exit code."""
    try:
        from ventra_ingester.enrichment import Enricher
        from ventra_ingester.pipeline import ingest_package
    except ImportError:
        print(
            "Ingest skipped: ventra-ingester is not installed.\n"
            "  The evidence package was sealed successfully.\n"
            "  Install the ingester (pip install -e ./ingester or make install), then run:\n"
            f"    ventra-ingest {package_path} --case-store {case_store}",
            file=sys.stderr,
        )
        return 0

    say = reporter or print
    say(f"\nIngesting into case store: {case_store.resolve()}")
    try:
        result = ingest_package(
            package_path,
            case_store,
            enricher=Enricher(),
            reporter=say,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Ingest failed: {exc}", file=sys.stderr)
        return 1

    say(
        f"\nCase {result.case_id} ready in {result.case_dir} "
        f"({result.event_count} events, integrity={result.integrity_overall})."
    )
    if result.sources_loaded:
        say(f"  Event sources: {', '.join(result.sources_loaded)}")
    if result.inventory_loaded:
        say(f"  Inventory:     {', '.join(result.inventory_loaded)}")
    for warning in result.warnings:
        say(f"  warning: {warning}")
    say(f"  Open the console and select case {result.case_id}.")
    return 0
