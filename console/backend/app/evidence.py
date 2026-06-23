"""Browse raw evidence files extracted from the sealed package into ``cases/<id>/evidence/``."""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Any

from .config import settings

_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,512}$")


class EvidenceError(ValueError):
    pass


class EvidenceNotFound(EvidenceError):
    pass


def _evidence_root(case_dir: Path) -> Path:
    return case_dir / "evidence"


def _resolve_evidence_path(case_dir: Path, rel_path: str) -> Path:
    rel = rel_path.strip().lstrip("/").replace("\\", "/")
    if not rel or ".." in rel.split("/") or not _PATH_RE.fullmatch(rel):
        raise EvidenceError(f"Invalid evidence path: {rel_path!r}")
    root = _evidence_root(case_dir).resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise EvidenceError(f"Path escapes evidence root: {rel_path!r}")
    return target


def _manifest_source_meta(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("sources") or []:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "").strip()
        if path:
            out[path] = entry
        name = str(entry.get("name") or "").strip()
        if name and name not in out:
            out[name] = entry
    return out


def _classify_file(rel: str) -> str:
    name = rel.rsplit("/", 1)[-1]
    if name.startswith("events"):
        return "events"
    if name == "config.json":
        return "config"
    if name == "snapshot.json":
        return "snapshot"
    if name == "_meta.json":
        return "meta"
    if "credential_report" in name:
        return "credential_report"
    if rel.startswith("errors/"):
        return "error"
    if rel == "collection.log":
        return "collection_log"
    if rel == "manifest.json":
        return "manifest"
    if rel.endswith(".sig"):
        return "signature"
    return "other"


def ensure_evidence_extracted(case_dir: Path, case_id: str) -> Path:
    """Return the evidence directory, extracting from a retained package when missing."""
    root = _evidence_root(case_dir)
    if root.is_dir() and any(root.rglob("*")):
        return root

    from ventra_ingester.evidence_extract import extract_package, find_package_for_case

    pkg_dir = case_dir / "package"
    package = find_package_for_case(case_id, pkg_dir, settings.upload_dir)
    if package is None:
        raise EvidenceNotFound(
            f"No raw evidence files for case {case_id!r}. Re-import the sealed package."
        )
    extract_package(package, root)
    return root


def list_evidence_files(case_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    case_id = str(manifest.get("case_id") or case_dir.name)
    root = ensure_evidence_extracted(case_dir, case_id)
    meta_by_path = _manifest_source_meta(manifest)
    files: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        total_bytes += size
        manifest_entry = meta_by_path.get(rel) or meta_by_path.get(rel.split("/", 1)[0])
        source_name = ""
        if rel.startswith("sources/"):
            parts = rel.split("/")
            if len(parts) >= 2:
                source_name = parts[1]
        files.append(
            {
                "path": rel,
                "size": size,
                "kind": _classify_file(rel),
                "source": source_name or None,
                "sha256": (manifest_entry or {}).get("sha256"),
                "record_count": (manifest_entry or {}).get("record_count"),
                "status": (manifest_entry or {}).get("status"),
                "notes": (manifest_entry or {}).get("notes"),
            }
        )
    return {
        "case_id": case_id,
        "root": "evidence",
        "files": files,
        "total_files": len(files),
        "total_bytes": total_bytes,
    }


def read_evidence_text(case_dir: Path, rel_path: str, *, max_bytes: int | None = None) -> dict[str, Any]:
    target = _resolve_evidence_path(case_dir, rel_path)
    if not target.is_file():
        raise EvidenceNotFound(f"No evidence file at {rel_path!r}")
    size = target.stat().st_size
    cap = max_bytes if max_bytes is not None else size
    raw = target.read_bytes()[:cap]
    truncated = len(raw) < size
    if rel_path.endswith(".gz") and not rel_path.endswith(".tar.gz"):
        try:
            raw = gzip.decompress(raw)
            truncated = truncated or len(raw) >= cap
        except OSError:
            pass
    text = raw.decode("utf-8", errors="replace")
    content_type = "json" if rel_path.endswith(".json") else "text"
    if content_type == "json":
        try:
            parsed = json.loads(text)
            return {
                "path": rel_path,
                "size": size,
                "truncated": truncated,
                "content_type": "json",
                "json": parsed,
            }
        except json.JSONDecodeError:
            content_type = "text"
    return {
        "path": rel_path,
        "size": size,
        "truncated": truncated,
        "content_type": content_type,
        "text": text,
    }


def read_evidence_lines(
    case_dir: Path,
    rel_path: str,
    *,
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
    """Return JSON-lines records from an events file with optional pagination."""
    target = _resolve_evidence_path(case_dir, rel_path)
    if not target.is_file():
        raise EvidenceNotFound(f"No evidence file at {rel_path!r}")

    if limit is None:
        limit = 10_000_000

    data = target.read_bytes()
    if rel_path.endswith(".gz"):
        data = gzip.decompress(data)
    lines = data.decode("utf-8", errors="replace").splitlines()
    total_lines = len(lines)
    slice_lines = lines[offset : offset + limit]
    records: list[Any] = []
    for line in slice_lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"_raw": line})
    return {
        "path": rel_path,
        "total_lines": total_lines,
        "offset": offset,
        "count": len(records),
        "has_more": offset + len(slice_lines) < total_lines,
        "records": records,
    }


def read_evidence_bytes(case_dir: Path, rel_path: str) -> tuple[Path, str]:
    target = _resolve_evidence_path(case_dir, rel_path)
    if not target.is_file():
        raise EvidenceNotFound(f"No evidence file at {rel_path!r}")
    media = "application/octet-stream"
    if rel_path.endswith(".json"):
        media = "application/json"
    elif rel_path.endswith(".log"):
        media = "text/plain"
    elif rel_path.endswith(".gz"):
        media = "application/gzip"
    return target, media
