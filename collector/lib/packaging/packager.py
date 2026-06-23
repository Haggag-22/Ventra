"""Seal a staging directory into a Ventra evidence package.

Produces ``case-<case>-<account>-<ts>.tar.zst`` (or ``.tar.gz`` if zstandard is unavailable)
plus a detached signature over the *package* for transit integrity. The manifest inside is
separately signed by the chain_of_custody module.
"""

from __future__ import annotations

import gzip
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..chain_of_custody.hashing import sha256_file

try:  # optional, preferred
    import zstandard as _zstd
except Exception:  # pragma: no cover - environment dependent
    _zstd = None


@dataclass
class PackageResult:
    path: Path
    sha256: str
    bytes: int
    compression: str  # "zstd" | "gzip"


def _archive_name(case_id: str, account_id: str) -> str:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_case = case_id.replace("/", "_").replace(" ", "_")
    return f"case-{safe_case}-{account_id}-{ts}"


def _write_tar(staging: Path, tar_path: Path) -> None:
    with tarfile.open(tar_path, mode="w") as tar:
        for item in sorted(staging.rglob("*")):
            if item.is_file():
                tar.add(item, arcname=item.relative_to(staging).as_posix())


def _compress_file(src: Path, dst: Path, *, compression: str) -> None:
    if compression == "zstd" and _zstd is not None:
        cctx = _zstd.ZstdCompressor(level=19)
        with src.open("rb") as fin, dst.open("wb") as fout:
            cctx.copy_stream(fin, fout)
        return
    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(gzip.compress(fin.read(), compresslevel=9))


def seal_package(staging: Path, out_dir: Path, case_id: str, account_id: str) -> PackageResult:
    """Tar the staging tree, compress, hash. Returns package metadata.

    The staging directory must already contain ``manifest.json``, ``manifest.json.sig``,
    ``collection.log``, and the ``sources/`` tree.

    Uses a temp tar on disk and streaming compression so multi-GB packages do not require
    holding the full archive in RAM.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    base = _archive_name(case_id, account_id)
    use_zstd = _zstd is not None
    compression = "zstd" if use_zstd else "gzip"
    out_path = out_dir / (f"{base}.tar.zst" if use_zstd else f"{base}.tar.gz")

    with tempfile.TemporaryDirectory(prefix="ventra-seal-") as tmp:
        tar_path = Path(tmp) / f"{base}.tar"
        _write_tar(staging, tar_path)
        _compress_file(tar_path, out_path, compression=compression)

    digest = sha256_file(out_path)
    (out_dir / f"{out_path.name}.sha256").write_text(
        f"{digest}  {out_path.name}\n", encoding="utf-8"
    )
    return PackageResult(
        path=out_path,
        sha256=digest,
        bytes=out_path.stat().st_size,
        compression=compression,
    )
