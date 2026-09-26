"""Hostile evidence packages must never write or delete outside the case store."""

from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest
import zstandard

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_demo_case import generate  # noqa: E402

from ventra_ingester.evidence_extract import extract_package, safe_member_path  # noqa: E402
from ventra_ingester.loaders.casestore import CaseStore, safe_case_id  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


def _package(path: Path, members: dict[str, bytes]) -> Path:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    path.write_bytes(zstandard.ZstdCompressor().compress(raw.getvalue()))
    return path


def _rewrite_members(pkg: Path, out: Path, *, rename=None, edit_manifest=None) -> Path:
    """Copy a real sealed package, optionally renaming members or editing the manifest."""
    raw = zstandard.ZstdDecompressor().decompressobj().decompress(pkg.read_bytes())
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for m in tar.getmembers():
            if m.isfile():
                members[m.name] = tar.extractfile(m).read()
    if edit_manifest:
        manifest = json.loads(members["manifest.json"])
        edit_manifest(manifest)
        members["manifest.json"] = json.dumps(manifest).encode()
    if rename:
        members = {rename.get(k, k): v for k, v in members.items()}
    return _package(out, members)


@pytest.mark.parametrize("name", ["../x", "a/../../x", "/etc/x", "C:/x", "C:\\x", "..\\x", ""])
def test_safe_member_path_rejects_escapes(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError):
        safe_member_path(tmp_path / "dest", name)


def test_safe_member_path_allows_nested(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    assert (
        safe_member_path(dest, "sources/cloudtrail/a.jsonl.gz")
        == (dest / "sources" / "cloudtrail" / "a.jsonl.gz").resolve()
    )


@pytest.mark.parametrize("name", ["../ESCAPED.txt", "/tmp/ventra-escape-test.txt"])
def test_extract_refuses_whole_package_on_escape(tmp_path: Path, name: str) -> None:
    pkg = _package(tmp_path / "evil.tar.zst", {"manifest.json": b"{}", name: b"pwned"})
    dest = tmp_path / "store" / "case" / "evidence"
    dest.parent.mkdir(parents=True)
    with pytest.raises(ValueError, match="Unsafe path"):
        extract_package(pkg, dest)
    assert not (tmp_path / "store" / "case" / "ESCAPED.txt").exists()
    assert not Path("/tmp/ventra-escape-test.txt").exists()
    assert list(dest.iterdir()) == []  # nothing half-extracted


@pytest.mark.parametrize(
    "case_id", ["..", ".", "../outside", "a/b", "a\\b", ".hidden", "C:x", "x" * 129, "", "  ", "a\nb"]
)
def test_safe_case_id_rejects(case_id: str) -> None:
    with pytest.raises(ValueError):
        safe_case_id(case_id)


@pytest.mark.parametrize("case_id", ["CASE-2026-0042", "Acme Breach", "case_1.v2", "CASE-PENDING"])
def test_safe_case_id_accepts_collector_ids(case_id: str) -> None:
    assert safe_case_id(case_id) == case_id


def test_case_store_refuses_escaping_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        CaseStore(tmp_path / "cases", "../victim")


def test_ingest_rejects_manifest_case_id_traversal(tmp_path: Path) -> None:
    """A crafted manifest case_id must not rmtree a directory next to the case store."""
    real = generate(tmp_path / "pkg", "CASE-OK")
    evil = _rewrite_members(
        real, tmp_path / "evil.tar.zst", edit_manifest=lambda m: m.update(case_id="../victim")
    )
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("important")

    with pytest.raises(ValueError, match="Unsafe case id"):
        ingest_package(evil, tmp_path / "cases")
    assert (victim / "keep.txt").read_text() == "important"


def test_ingest_rejects_member_traversal(tmp_path: Path) -> None:
    real = generate(tmp_path / "pkg", "CASE-SLIP")
    evil = _rewrite_members(real, tmp_path / "evil.tar.zst", rename={"collection.log": "../../ESCAPED.log"})
    with pytest.raises(ValueError, match="Unsafe path"):
        ingest_package(evil, tmp_path / "cases")
    assert not (tmp_path / "ESCAPED.log").exists()
