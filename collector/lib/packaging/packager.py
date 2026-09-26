"""Seal a staging directory into a Ventra evidence package.

Produces ``case-<case>-<account>-<ts>.tar.zst`` (or ``.tar.gz`` if zstandard is unavailable)
plus a detached signature over the *package* for transit integrity. The manifest inside is
separately signed by the chain_of_custody module.
"""

from __future__ import annotations

import gzip
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

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


def staging_directory(out_dir: Path, prefix: str = "stage") -> tempfile.TemporaryDirectory[str]:
    """Scratch space for a collection run, created inside ``out_dir`` rather than ``/tmp``.

    Evidence is staged here and then sealed into ``out_dir``, so keeping it on the same filesystem
    means a run only needs disk where the operator pointed ``--out``. ``/tmp`` is often a small
    tmpfs (a fraction of RAM) on cluster nodes and would fill long before the real disk does.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=f".ventra-{prefix}-", dir=out_dir)


def _write_tar(
    staging: Path,
    fileobj: BinaryIO,
    *,
    on_progress: Callable[[str], None] | None = None,
) -> None:
    files = sorted(p for p in staging.rglob("*") if p.is_file())
    total = len(files)
    if on_progress is not None:
        on_progress(f"Archiving {total:,} evidence file(s)…")
    # Stream mode ("w|"): the tar goes straight into the compressor, never to disk uncompressed.
    with tarfile.open(fileobj=fileobj, mode="w|") as tar:
        for index, item in enumerate(files, start=1):
            tar.add(item, arcname=item.relative_to(staging).as_posix())
            if on_progress is not None and index % 25 == 0:
                on_progress(f"Archived {index:,}/{total:,} file(s)…")
    if on_progress is not None and total:
        on_progress(f"Archive built ({total:,} file(s))")


def _write_compressed_tar(
    staging: Path,
    dst: Path,
    *,
    compression: str,
    on_progress: Callable[[str], None] | None = None,
) -> None:
    if on_progress is not None:
        on_progress(f"Compressing archive ({compression})…")
    with dst.open("wb") as fout:
        if compression == "zstd" and _zstd is not None:
            cctx = _zstd.ZstdCompressor(level=19)
            with cctx.stream_writer(fout, closefd=False) as zout:
                _write_tar(staging, zout, on_progress=on_progress)
            return
        with gzip.GzipFile(fileobj=fout, mode="wb", compresslevel=9) as gzout:
            _write_tar(staging, gzout, on_progress=on_progress)


def seal_package(
    staging: Path,
    out_dir: Path,
    case_id: str,
    account_id: str,
    *,
    on_progress: Callable[[str], None] | None = None,
) -> PackageResult:
    """Tar the staging tree, compress, hash. Returns package metadata.

    The staging directory must already contain ``manifest.json``, ``manifest.json.sig``,
    ``collection.log``, and the ``sources/`` tree.

    The tar is streamed through the compressor, so neither RAM nor scratch disk has to hold an
    uncompressed copy of the archive.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    base = _archive_name(case_id, account_id)
    use_zstd = _zstd is not None
    compression = "zstd" if use_zstd else "gzip"
    out_path = out_dir / (f"{base}.tar.zst" if use_zstd else f"{base}.tar.gz")

    try:
        _write_compressed_tar(staging, out_path, compression=compression, on_progress=on_progress)
    except BaseException:
        out_path.unlink(missing_ok=True)
        raise

    if on_progress is not None:
        on_progress("Computing package checksum…")

    digest = sha256_file(out_path)
    (out_dir / f"{out_path.name}.sha256").write_text(f"{digest}  {out_path.name}\n", encoding="utf-8")
    return PackageResult(
        path=out_path,
        sha256=digest,
        bytes=out_path.stat().st_size,
        compression=compression,
    )
