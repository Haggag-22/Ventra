"""Extract sealed package members to ``cases/<id>/evidence/`` for console file browsing."""

from __future__ import annotations

import gzip
import io
import json
import shutil
import tarfile
from pathlib import Path

from .package import EvidencePackage


def _decompress_tar_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.name.endswith(".tar.zst") or path.suffix == ".zst":
        import zstandard

        return zstandard.ZstdDecompressor().decompress(raw, max_output_size=4_000_000_000)
    if path.name.endswith(".tar.gz") or path.suffix == ".gz":
        return gzip.decompress(raw)
    return raw


def extract_package(package_path: Path, dest: Path) -> int:
    """Write every file member from a sealed package under ``dest``, preserving paths.

    Returns the number of files written.
    """
    package_path = Path(package_path)
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    tar_bytes = _decompress_tar_bytes(package_path)
    count = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            target = dest / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            target.write_bytes(extracted.read())
            count += 1
    return count


def package_case_id(package_path: Path) -> str | None:
    """Read ``case_id`` from a package manifest without extracting."""
    try:
        return str(EvidencePackage(package_path).manifest.get("case_id") or "").strip() or None
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
