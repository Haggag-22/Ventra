"""A manifest signature the ingester cannot verify must never earn the green "verified" badge."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import zstandard

from ventra_ingester.package import EvidencePackage
from ventra_ingester.verify import verify_package


def _sealed_package(path: Path, signature: bytes | None) -> Path:
    """A one-source package whose hashes all match; only the signature varies."""
    events = b'{"eventName": "GetObject"}\n'
    manifest = json.dumps(
        {
            "case_id": "CASE-SIG",
            "sources": [
                {
                    "name": "cloudtrail",
                    "path": "sources/cloudtrail/events.jsonl",
                    "sha256": hashlib.sha256(events).hexdigest(),
                    "status": "collected",
                }
            ],
        }
    ).encode()
    members = {"manifest.json": manifest, "sources/cloudtrail/events.jsonl": events}
    if signature is not None:
        members["manifest.json.sig"] = signature
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    path.write_bytes(zstandard.ZstdCompressor().compress(raw.getvalue()))
    return path


def _verify(path: Path):
    with EvidencePackage(path) as pkg:
        return verify_package(pkg)


def test_forged_signature_is_not_reported_as_verified(tmp_path: Path) -> None:
    report = _verify(_sealed_package(tmp_path / "forged.tar.zst", b"not-a-real-signature\n"))
    assert report.overall == "amber"
    assert report.signature_method == "cosign/minisign-unverified"
    assert any("NOT verified" in n for n in report.notes)


def test_sha256_stamp_matching_is_amber(tmp_path: Path) -> None:
    pkg = _sealed_package(tmp_path / "stamp.tar.zst", None)
    with EvidencePackage(pkg) as p:
        stamp = hashlib.sha256(p.member_bytes("manifest.json")).hexdigest()
    report = _verify(_sealed_package(tmp_path / "stamp2.tar.zst", f"sha256-stamp:{stamp}\n".encode()))
    assert report.overall == "amber"
    assert report.signature_valid is True


def test_wrong_sha256_stamp_is_red(tmp_path: Path) -> None:
    report = _verify(_sealed_package(tmp_path / "bad.tar.zst", b"sha256-stamp:" + b"0" * 64 + b"\n"))
    assert report.overall == "red"


def test_missing_signature_is_red(tmp_path: Path) -> None:
    assert _verify(_sealed_package(tmp_path / "unsealed.tar.zst", None)).overall == "red"
