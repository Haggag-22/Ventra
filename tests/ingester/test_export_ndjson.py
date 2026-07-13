"""Tests for the generalized export_ndjson() — targets, batching, and scope filters.

The Elastic path is covered byte-for-byte by test_track_d.py / test_export_elastic.py (those
assert export_elastic_ndjson() is unchanged); this file covers the new multi-target surface:
splunk/ndjson shaping, and the sources/since/until filters pushed into the DuckDB query.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_demo_case import generate  # noqa: E402

from ventra_ingester.exporters.elastic_ndjson import export_ndjson  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


@pytest.fixture(scope="module")
def ingested_case(tmp_path_factory) -> Path:
    pkg_dir = tmp_path_factory.mktemp("pkg")
    store = tmp_path_factory.mktemp("cases")
    pkg = generate(pkg_dir, "CASE-EXPORT-NDJSON")
    result = ingest_package(pkg, store)
    return store / result.case_id


def test_unknown_target_raises(tmp_path: Path, ingested_case: Path) -> None:
    with pytest.raises(ValueError):
        export_ndjson(ingested_case, tmp_path / "out", target="datadog")


def test_ndjson_target_is_unwrapped(tmp_path: Path, ingested_case: Path) -> None:
    out = tmp_path / "out-ndjson"
    written = export_ndjson(ingested_case, out, target="ndjson")
    assert written
    manifest = json.loads((out / "export-manifest.json").read_text())
    assert manifest["format"] == "ndjson"
    assert manifest["target"] == "ndjson"

    first = next(iter(written.values()))
    sample = json.loads(first.read_text(encoding="utf-8").splitlines()[0])
    # No Elastic-style wrapping: the raw normalized fields pass through untouched.
    assert "@timestamp" not in sample
    assert "ventra" not in sample
    assert sample["case_id"] == "CASE-EXPORT-NDJSON"
    # No target-specific extra file for the generic target.
    extras = [p.name for p in out.iterdir() if p.suffix != ".ndjson" and p.name != "export-manifest.json"]
    assert extras == []


def test_splunk_target_hec_envelope(tmp_path: Path, ingested_case: Path) -> None:
    out = tmp_path / "out-splunk"
    written = export_ndjson(ingested_case, out, target="splunk")
    assert written
    manifest = json.loads((out / "export-manifest.json").read_text())
    assert manifest["format"] == "splunk-cim-hec-ndjson"

    first = next(iter(written.values()))
    sample = json.loads(first.read_text(encoding="utf-8").splitlines()[0])
    assert sample["host"] == "CASE-EXPORT-NDJSON"
    assert sample["source"].startswith("ventra:")
    assert sample["sourcetype"] == sample["source"]
    assert isinstance(sample["event"], dict)
    assert "time" in sample  # epoch seconds, extracted from the event timestamp

    event = sample["event"]
    # CIM fields — no flat UnifiedEvent leftovers inside event.
    assert "event_action" not in event
    assert "source_ip" not in event
    assert "case_id" not in event
    assert event["ventra_case_id"] == "CASE-EXPORT-NDJSON"
    assert event["ventra_source"]
    assert "raw" in event
    # At least one of the core CIM fields should be present on demo events.
    assert any(k in event for k in ("action", "user", "src", "src_ip", "app", "vendor_product", "status"))

    assert (out / "splunk-loading-instructions.md").is_file()
    instructions = (out / "splunk-loading-instructions.md").read_text()
    assert "CIM" in instructions


def test_elastic_target_writes_index_template(tmp_path: Path, ingested_case: Path) -> None:
    out = tmp_path / "out-elastic-extra"
    written = export_ndjson(ingested_case, out, target="elastic")
    template = json.loads((out / "elastic-index-template.json").read_text())
    assert "index_patterns" in template
    assert template["template"]["mappings"]["properties"]["event"]["properties"]["action"]["type"] == "keyword"

    first = next(iter(written.values()))
    sample = json.loads(first.read_text(encoding="utf-8").splitlines()[0])
    # ECS nested — no flat UnifiedEvent leftovers.
    assert "event_action" not in sample
    assert "cloud_provider" not in sample
    assert "source_ip" not in sample
    assert isinstance(sample["event"], dict)
    assert isinstance(sample["cloud"], dict)
    assert sample["ventra"]["case_id"] == "CASE-EXPORT-NDJSON"
    assert "@timestamp" in sample
    assert "raw" in sample
    manifest = json.loads((out / "export-manifest.json").read_text())
    assert manifest["format"] == "elastic-ecs-ndjson"


def test_source_filter_restricts_exported_sources(tmp_path: Path, ingested_case: Path) -> None:
    out_all = tmp_path / "out-all"
    written_all = export_ndjson(ingested_case, out_all, target="ndjson")
    assert len(written_all) > 1, "fixture must span multiple sources for this test to be meaningful"

    one_source = next(iter(written_all.keys()))
    out_filtered = tmp_path / "out-filtered"
    written_filtered = export_ndjson(ingested_case, out_filtered, target="ndjson", sources=[one_source])

    assert set(written_filtered.keys()) == {one_source}
    manifest = json.loads((out_filtered / "export-manifest.json").read_text())
    assert manifest["sources"] == [one_source]
    assert manifest["source_filter"] == [one_source]
    assert manifest["total_events"] == written_all[one_source].read_text().count("\n")


def test_date_filter_excludes_out_of_range_events(tmp_path: Path, ingested_case: Path) -> None:
    out_unfiltered = tmp_path / "out-unfiltered"
    written = export_ndjson(ingested_case, out_unfiltered, target="ndjson")
    total_unfiltered = sum(p.read_text().count("\n") for p in written.values())

    # A window far in the future excludes every event.
    out_future = tmp_path / "out-future"
    export_ndjson(
        ingested_case, out_future, target="ndjson", since="2999-01-01T00:00:00Z",
    )
    manifest_future = json.loads((out_future / "export-manifest.json").read_text())
    assert manifest_future["total_events"] == 0
    assert manifest_future["since"] == "2999-01-01T00:00:00Z"

    # A window covering all of recorded history matches the unfiltered count.
    out_wide = tmp_path / "out-wide"
    export_ndjson(
        ingested_case, out_wide, target="ndjson",
        since="2000-01-01T00:00:00Z", until="2999-01-01T00:00:00Z",
    )
    manifest_wide = json.loads((out_wide / "export-manifest.json").read_text())
    assert manifest_wide["total_events"] == total_unfiltered


def test_batch_of_multiple_cases(tmp_path: Path, tmp_path_factory) -> None:
    """Exporting N cases is just calling export_ndjson() once per case — verify each is
    independent (own manifest, own event counts) and none leak into another's output."""
    pkg_dir = tmp_path_factory.mktemp("pkg2")
    store = tmp_path_factory.mktemp("cases2")
    case_ids = ["CASE-BATCH-A", "CASE-BATCH-B", "CASE-BATCH-C"]
    case_dirs = []
    for cid in case_ids:
        pkg = generate(pkg_dir / cid, cid)
        result = ingest_package(pkg, store)
        case_dirs.append(store / result.case_id)

    combined_total = 0
    for cid, case_dir in zip(case_ids, case_dirs, strict=True):
        out = tmp_path / cid
        written = export_ndjson(case_dir, out, target="ndjson")
        manifest = json.loads((out / "export-manifest.json").read_text())
        assert manifest["case_id"] == cid
        for path in written.values():
            for line in path.read_text(encoding="utf-8").splitlines():
                assert json.loads(line)["case_id"] == cid
        combined_total += manifest["total_events"]

    assert combined_total > 0
