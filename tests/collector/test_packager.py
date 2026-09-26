"""Sealing stays on the ``--out`` filesystem and never writes an uncompressed tar."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from collector.lib.packaging import packager
from collector.lib.packaging.packager import seal_package, staging_directory


def _make_staging(root: Path) -> Path:
    (root / "sources" / "demo").mkdir(parents=True)
    (root / "manifest.json").write_text('{"case_id":"C1"}')
    (root / "manifest.json.sig").write_text("sha256-stamp:abc")
    (root / "collection.log").write_text("")
    (root / "sources" / "demo" / "events.jsonl").write_bytes(b'{"n":1}\n' * 1000)
    return root


def _members(path: Path) -> dict[str, bytes]:
    raw = path.read_bytes()
    if path.name.endswith(".zst"):
        raw = packager._zstd.ZstdDecompressor().decompressobj().decompress(raw)
    else:
        raw = gzip.decompress(raw)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


def test_staging_directory_lives_inside_out_dir_and_is_removed(tmp_path: Path) -> None:
    out = tmp_path / "does" / "not" / "exist"
    with staging_directory(out, "stage") as tmp:
        staging = Path(tmp)
        assert staging.parent == out
        assert staging.name.startswith(".ventra-stage-")
    assert not staging.exists()
    assert list(out.iterdir()) == []


@pytest.mark.parametrize("use_zstd", [True, False])
def test_seal_round_trips_without_temp_tar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, use_zstd: bool
) -> None:
    if use_zstd and packager._zstd is None:
        pytest.skip("zstandard not installed")
    if not use_zstd:
        monkeypatch.setattr(packager, "_zstd", None)
    staging = _make_staging(tmp_path / "staging")
    out = tmp_path / "out"

    result = seal_package(staging, out, "C1", "cluster")

    assert result.compression == ("zstd" if use_zstd else "gzip")
    assert sorted(p.name for p in out.iterdir()) == sorted([result.path.name, f"{result.path.name}.sha256"])
    members = _members(result.path)
    assert members["sources/demo/events.jsonl"] == b'{"n":1}\n' * 1000
    assert set(members) == {
        "manifest.json",
        "manifest.json.sig",
        "collection.log",
        "sources/demo/events.jsonl",
    }


def test_seal_failure_removes_partial_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging = _make_staging(tmp_path / "staging")
    out = tmp_path / "out"

    def boom(*_args: object, **_kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(packager, "_write_tar", boom)
    with pytest.raises(OSError):
        seal_package(staging, out, "C1", "cluster")
    assert list(out.iterdir()) == []
