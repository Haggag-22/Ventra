"""Open and read a Ventra evidence package.

Handles both ``.tar.zst`` and ``.tar.gz`` containers. Streams decompression to a temp tar on
disk for random member access without loading the full archive into RAM.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .limits import MAX_DECOMPRESS_BYTES


def _decompress_to_tar(package_path: Path, work_dir: Path) -> Path:
    """Stream-decompress a sealed package to an uncompressed tar file."""
    package_path = Path(package_path)
    if package_path.name.endswith(".tar.zst"):
        tar_path = work_dir / package_path.name.replace(".tar.zst", ".tar")
        if tar_path.exists() and tar_path.stat().st_size > 0:
            return tar_path
        try:
            import zstandard
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Reading .tar.zst requires zstandard (pip install zstandard)") from exc
        dctx = zstandard.ZstdDecompressor()
        with package_path.open("rb") as src, tar_path.open("wb") as dst:
            with dctx.stream_reader(src) as reader:
                total = 0
                while True:
                    chunk = reader.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DECOMPRESS_BYTES:
                        raise ValueError(
                            f"Package exceeds decompression limit ({MAX_DECOMPRESS_BYTES} bytes). "
                            "Raise VENTRA_MAX_DECOMPRESS_BYTES for larger packages."
                        )
                    dst.write(chunk)
        return tar_path

    if package_path.name.endswith(".tar.gz"):
        tar_path = work_dir / package_path.name.replace(".tar.gz", ".tar")
        if tar_path.exists() and tar_path.stat().st_size > 0:
            return tar_path
        with gzip.open(package_path, "rb") as src, tar_path.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        return tar_path

    return package_path


@dataclass
class SourceFile:
    name: str  # logical source, e.g. "cloudtrail"
    arcname: str  # full path within archive
    kind: str  # "events" | "config" | "snapshot" | "meta" | "credential_report" | "other"


class EvidencePackage:
    """Disk-backed view over a sealed package (temp tar extracted on demand)."""

    def __init__(self, path: Path, *, work_dir: Path | None = None) -> None:
        self.path = Path(path)
        self._owns_work = work_dir is None
        self._work_dir = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="ventra-pkg-"))
        self._tar_path = _decompress_to_tar(self.path, self._work_dir)
        self._cache: dict[str, bytes] = {}
        with tarfile.open(self._tar_path, mode="r:") as tar:
            manifest_member = tar.getmember("manifest.json")
            manifest_file = tar.extractfile(manifest_member)
            if manifest_file is None:
                raise ValueError(f"{path} is not a Ventra package: no manifest.json")
            self.manifest: dict[str, Any] = json.loads(manifest_file.read())

    def close(self) -> None:
        if self._owns_work and self._work_dir.exists():
            shutil.rmtree(self._work_dir, ignore_errors=True)

    def __enter__(self) -> EvidencePackage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _read_member_bytes(self, arcname: str) -> bytes | None:
        if arcname in self._cache:
            return self._cache[arcname]
        with tarfile.open(self._tar_path, mode="r:") as tar:
            try:
                member = tar.getmember(arcname)
            except KeyError:
                return None
            extracted = tar.extractfile(member)
            if extracted is None:
                return None
            data = extracted.read()
        self._cache[arcname] = data
        return data

    def member_bytes(self, arcname: str) -> bytes | None:
        return self._read_member_bytes(arcname)

    def member_sha256(self, arcname: str) -> str | None:
        """Hash a member by streaming from tar without caching the full payload."""
        with tarfile.open(self._tar_path, mode="r:") as tar:
            try:
                member = tar.getmember(arcname)
            except KeyError:
                return None
            extracted = tar.extractfile(member)
            if extracted is None:
                return None
            h = hashlib.sha256()
            while True:
                chunk = extracted.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
            return h.hexdigest()

    def manifest_signature(self) -> bytes | None:
        return self._read_member_bytes("manifest.json.sig")

    def collection_log(self) -> list[dict[str, Any]]:
        raw = self._read_member_bytes("collection.log") or b""
        out = []
        for line in raw.decode("utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def source_files(self) -> list[SourceFile]:
        out: list[SourceFile] = []
        with tarfile.open(self._tar_path, mode="r:") as tar:
            for member in tar.getmembers():
                if not member.isfile() or not member.name.startswith("sources/"):
                    continue
                parts = member.name.split("/")
                if len(parts) < 3:
                    continue
                name = parts[1]
                fname = parts[-1]
                kind = self._classify(fname)
                out.append(SourceFile(name=name, arcname=member.name, kind=kind))
        return out

    def sources(self) -> set[str]:
        return {sf.name for sf in self.source_files()}

    def read_records(self, arcname: str) -> Iterator[dict[str, Any]]:
        """Yield records from a source file. Handles gzipped JSON-lines and plain JSON."""
        with tarfile.open(self._tar_path, mode="r:") as tar:
            try:
                member = tar.getmember(arcname)
            except KeyError:
                return
            extracted = tar.extractfile(member)
            if extracted is None:
                return
            if arcname.endswith(".gz") or arcname.endswith(".jsonl.gz"):
                with gzip.GzipFile(fileobj=extracted) as gz:
                    for line in gz:
                        text = line.decode("utf-8").strip()
                        if text:
                            yield json.loads(text)
            elif arcname.endswith(".json"):
                obj = json.loads(extracted.read().decode("utf-8"))
                if isinstance(obj, list):
                    yield from obj
                else:
                    yield obj

    def read_json(self, arcname: str) -> Any:
        data = self._read_member_bytes(arcname)
        return json.loads(data.decode("utf-8")) if data else None

    @staticmethod
    def _classify(fname: str) -> str:
        if fname.startswith("events"):
            return "events"
        if fname == "config.json":
            return "config"
        if fname == "snapshot.json":
            return "snapshot"
        if fname == "_meta.json":
            return "meta"
        if "credential_report" in fname:
            return "credential_report"
        return "other"
