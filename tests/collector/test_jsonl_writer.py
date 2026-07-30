"""Tests for streaming JSONL writer hash consistency."""

from __future__ import annotations

import hashlib
from pathlib import Path

from collector.lib.base import JsonlWriter


def test_jsonl_writer_reports_progress(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl.gz"
    seen: list[tuple[int, bool]] = []

    def on_progress(count: int, force: bool) -> None:
        seen.append((count, force))

    with JsonlWriter(out, relative_to=tmp_path, on_progress=on_progress, progress_every=2) as writer:
        for i in range(5):
            writer.write_record({"event_id": str(i)})
        writer.finalize()

    assert (2, False) in seen
    assert (4, False) in seen
    assert seen[-1] == (5, True)


def test_jsonl_writer_finalize_matches_sealed_file(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl.gz"
    with JsonlWriter(out, relative_to=tmp_path) as writer:
        writer.write_record({"event_id": "abc"})
        wf = writer.finalize()

    data = out.read_bytes()
    assert wf.sha256 == hashlib.sha256(data).hexdigest()
    assert wf.bytes == len(data)
    assert wf.record_count == 1
