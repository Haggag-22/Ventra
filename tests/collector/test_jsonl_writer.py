"""Tests for streaming JSONL writer hash consistency."""

from __future__ import annotations

import hashlib
from pathlib import Path

from collector.lib.base import JsonlWriter


def test_jsonl_writer_finalize_matches_sealed_file(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl.gz"
    with JsonlWriter(out, relative_to=tmp_path) as writer:
        writer.write_record({"event_id": "abc"})
        wf = writer.finalize()

    data = out.read_bytes()
    assert wf.sha256 == hashlib.sha256(data).hexdigest()
    assert wf.bytes == len(data)
    assert wf.record_count == 1
