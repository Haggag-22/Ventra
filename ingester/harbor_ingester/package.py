"""Open and read a Harbor evidence package.

Handles both ``.tar.zst`` and ``.tar.gz`` containers. Exposes the manifest and a way to read
each source file (gzip JSON-lines or plain JSON) without unpacking the whole archive to disk.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


def _decompress(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.name.endswith(".tar.zst") or path.suffix == ".zst":
        try:
            import zstandard
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Reading .tar.zst requires zstandard (pip install zstandard)") from exc
        return zstandard.ZstdDecompressor().decompress(raw, max_output_size=4_000_000_000)
    if path.name.endswith(".tar.gz") or path.suffix == ".gz":
        return gzip.decompress(raw)
    # Already a tar?
    return raw


@dataclass
class SourceFile:
    name: str  # logical source, e.g. "cloudtrail"
    arcname: str  # full path within archive
    kind: str  # "events" | "config" | "snapshot" | "meta" | "credential_report" | "other"


class EvidencePackage:
    """In-memory view over a sealed package."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._tar_bytes = _decompress(self.path)
        self._members: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(self._tar_bytes)) as tar:
            for m in tar.getmembers():
                if m.isfile():
                    self._members[m.name] = tar.extractfile(m).read()
        if "manifest.json" not in self._members:
            raise ValueError(f"{path} is not a Harbor package: no manifest.json")
        self.manifest: dict[str, Any] = json.loads(self._members["manifest.json"])

    # -- raw member access ---------------------------------------------------------------

    def member_bytes(self, arcname: str) -> bytes | None:
        return self._members.get(arcname)

    def manifest_signature(self) -> bytes | None:
        return self._members.get("manifest.json.sig")

    def collection_log(self) -> list[dict[str, Any]]:
        raw = self._members.get("collection.log", b"")
        out = []
        for line in raw.decode("utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    # -- source iteration ----------------------------------------------------------------

    def source_files(self) -> list[SourceFile]:
        out: list[SourceFile] = []
        for arc in self._members:
            if not arc.startswith("sources/"):
                continue
            parts = arc.split("/")
            if len(parts) < 3:
                continue
            name = parts[1]
            fname = parts[-1]
            kind = self._classify(fname)
            out.append(SourceFile(name=name, arcname=arc, kind=kind))
        return out

    def sources(self) -> set[str]:
        return {sf.name for sf in self.source_files()}

    def read_records(self, arcname: str) -> Iterator[dict[str, Any]]:
        """Yield records from a source file. Handles gzipped JSON-lines and plain JSON."""
        data = self._members.get(arcname)
        if data is None:
            return
        if arcname.endswith(".gz") or arcname.endswith(".jsonl.gz"):
            data = gzip.decompress(data)
            for line in data.decode("utf-8").splitlines():
                if line.strip():
                    yield json.loads(line)
        elif arcname.endswith(".json"):
            obj = json.loads(data.decode("utf-8"))
            # Snapshots/configs are single documents; yield the doc itself.
            if isinstance(obj, list):
                yield from obj
            else:
                yield obj

    def read_json(self, arcname: str) -> Any:
        data = self._members.get(arcname)
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
