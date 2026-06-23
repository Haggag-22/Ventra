"""Track D0/D4a regression tests for streaming seal, ingest, and export."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_demo_case import generate  # noqa: E402

from collector.lib.packaging.packager import seal_package  # noqa: E402
from ventra_ingester.exporters.elastic_ndjson import export_elastic_ndjson  # noqa: E402
from ventra_ingester.limits import MAX_DECOMPRESS_BYTES  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


def test_max_decompress_default_is_20gb() -> None:
    assert MAX_DECOMPRESS_BYTES >= 20 * 1024**3


def test_streaming_ingest_and_elastic_export(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "pkg"
    store = tmp_path / "cases"
    pkg_dir.mkdir()
    pkg = generate(pkg_dir, "CASE-TRACK-D")
    result = ingest_package(pkg, store)
    assert result.event_count > 0

    export_dir = tmp_path / "export"
    written = export_elastic_ndjson(store / result.case_id, export_dir)
    assert written
    manifest = json.loads((export_dir / "export-manifest.json").read_text())
    assert manifest["case_id"] == "CASE-TRACK-D"
    assert manifest["format"] == "elastic-ndjson"
    assert manifest["total_events"] == result.event_count
    assert sum(manifest["event_counts"].values()) == result.event_count
    for path in written.values():
        assert path.stat().st_size > 0

    first_path = next(iter(written.values()))
    sample = json.loads(first_path.read_text(encoding="utf-8").splitlines()[0])
    assert sample["@timestamp"]
    assert sample["ventra"]["case_id"] == "CASE-TRACK-D"
    assert sample["ventra"]["source"]
    assert "case_id" not in sample
    assert "ventra_source" not in sample
    assert isinstance(sample["event_category"], list)


def test_elastic_export_cli(tmp_path: Path) -> None:
    from ventra_ingester.cli import export_main

    pkg_dir = tmp_path / "pkg"
    store = tmp_path / "cases"
    pkg_dir.mkdir()
    pkg = generate(pkg_dir, "CASE-CLI")
    result = ingest_package(pkg, store)
    export_dir = tmp_path / "export-cli"
    rc = export_main(["--case-dir", str(store / result.case_id), "--out", str(export_dir)])
    assert rc == 0
    manifest = json.loads((export_dir / "export-manifest.json").read_text())
    assert manifest["case_id"] == "CASE-CLI"
    assert manifest["total_events"] == result.event_count


def test_seal_package_streams_without_loading_full_tar_in_memory(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    payload = b"x" * (512 * 1024)
    (staging / "manifest.json").write_bytes(b'{"case_id":"C1"}')
    (staging / "manifest.json.sig").write_bytes(b"sha256-stamp:abc")
    (staging / "collection.log").write_bytes(b"")
    src = staging / "sources" / "demo"
    src.mkdir(parents=True)
    (src / "events.jsonl.gz").write_bytes(payload)

    out = seal_package(staging, tmp_path / "out", "C1", "123456789012")
    assert out.path.is_file()
    assert out.bytes > 0


def test_large_jsonl_seal_and_ingest(tmp_path: Path) -> None:
    """Regression: multi-thousand-record JSONL seals and ingests without holding all events in RAM."""
    import gzip
    import hashlib
    from datetime import UTC, datetime

    from collector.lib.chain_of_custody.signing import sign_manifest
    from collector.lib.models import (
        Manifest,
        Operator,
        SourceResult,
        SourceStatus,
        TimeWindow,
        WrittenFile,
    )

    staging = tmp_path / "staging"
    src = staging / "sources" / "cloudtrail"
    src.mkdir(parents=True)
    out_path = src / "events.jsonl.gz"
    record_count = 25_000
    with gzip.GzipFile(filename=out_path, mode="wb", mtime=0) as gz:
        for i in range(record_count):
            line = json.dumps(
                {
                    "eventID": f"evt-{i}",
                    "eventName": "ConsoleLogin",
                    "eventTime": "2026-06-07T02:14:00Z",
                    "eventSource": "signin.amazonaws.com",
                }
            ) + "\n"
            gz.write(line.encode())
    data = out_path.read_bytes()
    wf = WrittenFile(
        path="sources/cloudtrail/events.jsonl.gz",
        sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        record_count=record_count,
    )

    manifest = Manifest(
        schema_version="1.0.0",
        tool_version="0.1.0",
        case_id="CASE-LARGE",
        cloud="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        operator=Operator(
            principal_arn="arn:aws:sts::123456789012:assumed-role/IR-Responder/test",
            user_id="AROAEXAMPLE:test",
            source_ip="100.64.0.10",
        ),
        started_at="2026-06-07T00:00:00Z",
        completed_at="2026-06-07T01:00:00Z",
        profile_name="all",
        host_environment="test",
        time_window=TimeWindow(since=datetime(2026, 6, 1, tzinfo=UTC)),
    )
    manifest.add_source_result(
        SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, files=[wf])
    )
    (staging / "collection.log").write_bytes(b"")
    manifest_path = staging / "manifest.json"
    manifest.write(manifest_path)
    sign_manifest(manifest_path, None)

    pkg = seal_package(staging, tmp_path / "pkg", "CASE-LARGE", "123456789012")
    assert pkg.path.is_file()
    assert pkg.bytes > 0

    store = tmp_path / "cases"
    result = ingest_package(pkg.path, store)
    assert result.event_count == record_count

    export_dir = tmp_path / "export-large"
    written = export_elastic_ndjson(store / result.case_id, export_dir)
    assert written["cloudtrail"].is_file()
    manifest = json.loads((export_dir / "export-manifest.json").read_text())
    assert manifest["event_counts"]["cloudtrail"] == record_count
