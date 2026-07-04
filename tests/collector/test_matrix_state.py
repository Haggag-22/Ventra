"""Unit tests for shared matrix state."""

from __future__ import annotations

from collector.engine.matrix_state import MatrixState, classify
from collector.lib.models import GapReason, SourceResult, SourceStatus


def test_begin_run_prepopulates_collectors() -> None:
    state = MatrixState()
    state.begin_run("123456789012", ["us-east-1"], "CASE-1", ["cloudtrail", "iam"])
    assert state.order == ["cloudtrail", "iam"]
    snap = state.snapshot()
    assert snap["total"] == 2
    assert snap["complete"] == 0
    assert len(snap["collectors"]) == 2
    assert snap["collectors"][0]["status"] == "pending"


def test_finish_pass_and_fail() -> None:
    state = MatrixState()
    state.begin_run("acct", [], "CASE-1", ["cloudtrail", "lambda"])
    state.start("cloudtrail")
    state.finish(
        "cloudtrail",
        SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, record_count=42),
    )
    state.start("lambda")
    state.finish(
        "lambda",
        SourceResult(
            name="lambda",
            status=SourceStatus.SKIPPED,
            gaps=[("lambda", GapReason.SERVICE_NOT_ENABLED, "not enabled")],
        ),
    )
    done, total = state.progress()
    assert done == 2
    assert total == 2
    assert state.rows["cloudtrail"].status == "pass"
    assert state.rows["lambda"].status == "fail"
    assert state.rows["cloudtrail"].records == 42
    gaps = state.coverage_gaps()
    assert len(gaps) == 1
    assert gaps[0]["collector"] == "lambda"


def test_classify_collected_is_pass() -> None:
    assert classify(SourceStatus.COLLECTED, "High") == "PASS"
    assert classify(SourceStatus.SKIPPED, "High") == "FAIL"
