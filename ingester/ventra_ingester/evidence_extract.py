"""Extract sealed package members to ``cases/<id>/evidence/`` for console file browsing."""

from __future__ import annotations

import gzip
import json
import shutil
import tarfile
from pathlib import Path

from .limits import MAX_DECOMPRESS_BYTES
from .package import _decompress_to_tar


def extract_package(package_path: Path, dest: Path) -> int:
    """Write every file member from a sealed package under ``dest``, preserving paths.

    Returns the number of files written.
    """
    package_path = Path(package_path)
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    work = dest.parent / f".{dest.name}.extract-work"
    work.mkdir(parents=True, exist_ok=True)
    try:
        tar_path = _decompress_to_tar(package_path, work)
        count = 0
        with tarfile.open(tar_path, mode="r:") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                target = dest / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                with target.open("wb") as out:
                    written = 0
                    while True:
                        chunk = extracted.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_DECOMPRESS_BYTES:
                            raise ValueError("Package member exceeds decompression limit during extract.")
                        out.write(chunk)
                count += 1
        return count
    finally:
        shutil.rmtree(work, ignore_errors=True)


def package_case_id(package_path: Path) -> str | None:
    """Read ``case_id`` from a package manifest without extracting."""
    from .package import EvidencePackage

    try:
        with EvidencePackage(package_path) as pkg:
            return str(pkg.manifest.get("case_id") or "").strip() or None
    except (ValueError, OSError, json.JSONDecodeError):
        return None


def find_package_for_case(case_id: str, *search_dirs: Path) -> Path | None:
    """Locate a sealed package whose manifest ``case_id`` matches."""
    cid = case_id.strip()
    if not cid:
        return None
    seen: set[Path] = set()
    for root in search_dirs:
        root = Path(root)
        if not root.is_dir():
            continue
        for pattern in ("*.tar.zst", "*.tar.gz", "*.tgz"):
            for path in sorted(root.glob(pattern)):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                if package_case_id(path) == cid:
                    return path
    return None
