"""Tests for evidence package extraction."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_demo_case import generate  # noqa: E402

from ventra_ingester.evidence_extract import extract_package, package_case_id  # noqa: E402
from ventra_ingester.pipeline import ingest_package  # noqa: E402


def test_extract_package_writes_members(tmp_path: Path) -> None:
    out_pkg = generate(tmp_path, "CASE-EVIDENCE-EXTRACT")
    dest = tmp_path / "evidence"
    count = extract_package(out_pkg, dest)
    assert count > 0
    assert (dest / "manifest.json").is_file()
    assert any(dest.glob("sources/*/*"))


def test_package_case_id_reads_manifest(tmp_path: Path) -> None:
    out_pkg = generate(tmp_path, "CASE-EVIDENCE-ID")
    assert package_case_id(out_pkg) == "CASE-EVIDENCE-ID"


def test_ingest_writes_evidence_tree(tmp_path: Path) -> None:
    pkg = generate(tmp_path, "CASE-EVIDENCE-INGEST")
    store = tmp_path / "cases"
    result = ingest_package(pkg, store)
    evidence = result.case_dir / "evidence"
    assert evidence.is_dir()
    assert (evidence / "manifest.json").is_file()
    assert any(evidence.glob("sources/*/*"))
