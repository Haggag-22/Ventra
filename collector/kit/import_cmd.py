"""Import a sealed evidence package (or output directory) into a case store."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ImportError_(Exception):
    """Import failed (named to avoid clashing with builtins.ImportError)."""


def find_evidence_package(path: Path) -> Path:
    """Resolve ``path`` to a sealed ``.tar.zst`` / ``.tar.gz`` evidence package."""
    path = path.expanduser().resolve()
    if path.is_file():
        name = path.name.lower()
        if name.endswith((".tar.zst", ".tar.gz", ".tgz")):
            return path
        raise ImportError_(f"not an evidence package: {path}")
    if not path.is_dir():
        raise ImportError_(f"path not found: {path}")

    candidates: list[Path] = []
    for pattern in ("*.tar.zst", "*.tar.gz", "*.tgz"):
        candidates.extend(path.glob(pattern))
        candidates.extend(path.glob(f"**/{pattern}"))
    # Prefer packages directly under the out dir.
    direct = [p for p in candidates if p.parent == path]
    pool = direct or candidates
    if not pool:
        raise ImportError_(f"no sealed evidence package (.tar.zst) found under {path}")
    pool.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return pool[0]


def case_id_from_package(package_path: Path) -> str:
    """Read case_id from the package manifest without full ingest."""
    try:
        from ventra_ingester.package import EvidencePackage
    except ImportError as exc:
        raise ImportError_(
            "ventra-ingester is not installed. Install it to import packages "
            "(pip install -e ./ingester)."
        ) from exc

    with EvidencePackage(package_path) as pkg:
        case_id = str(pkg.manifest.get("case_id") or "").strip()
    if not case_id:
        # Fall back to cli_run.json written by ventra run.
        custody = package_path.parent / "cli_run.json"
        if custody.is_file():
            data = json.loads(custody.read_text(encoding="utf-8"))
            case_id = str(data.get("case_id") or "").strip()
    if not case_id:
        raise ImportError_(f"package has no case_id in manifest: {package_path}")
    return case_id


def import_evidence(
    path: Path,
    *,
    into_case_id: str | None = None,
    case_store: Path | None = None,
) -> dict[str, Any]:
    """Import evidence into the local case store (same path as console package import)."""
    from collector.lib.ingest import default_case_store

    package = find_evidence_package(path)
    case_id = (into_case_id or "").strip() or case_id_from_package(package)
    store = (case_store or default_case_store()).expanduser().resolve()

    try:
        from ventra_ingester.enrichment import Enricher
        from ventra_ingester.pipeline import ingest_package
    except ImportError as exc:
        raise ImportError_(
            "ventra-ingester is not installed. Install it to import packages "
            "(pip install -e ./ingester)."
        ) from exc

    result = ingest_package(
        package,
        store,
        case_id_override=case_id,
        enricher=Enricher(),
        reporter=print,
    )
    return {
        "case_id": result.case_id,
        "case_dir": str(result.case_dir),
        "events": result.event_count,
        "integrity": result.integrity_overall,
        "sources_loaded": list(result.sources_loaded),
        "inventory_loaded": list(result.inventory_loaded),
        "warnings": list(result.warnings),
        "package": str(package),
    }
