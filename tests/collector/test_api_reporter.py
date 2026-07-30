"""ApiReporter persists matrix snapshots to a run sink."""

from __future__ import annotations

from typing import Any

from collector.engine.api_reporter import ApiReporter
from collector.engine.matrix_state import MatrixState
from collector.lib.models import SourceResult, SourceStatus


class _MemorySink:
    def __init__(self) -> None:
        self.matrix_updates: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.meta: list[dict[str, Any]] = []

    def update_matrix(self, run_id: str, matrix: dict[str, Any]) -> None:
        self.matrix_updates.append({"run_id": run_id, "matrix": matrix})

    def append_event(self, run_id: str, event: dict[str, Any]) -> None:
        self.events.append({"run_id": run_id, **event})

    def update_meta(self, run_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        self.meta.append({"run_id": run_id, **patch})
        return patch


def test_api_reporter_event_updates_live_records() -> None:
    sink = _MemorySink()
    matrix = MatrixState(severity_resolver=lambda _n: "High")
    reporter = ApiReporter(matrix, run_id="run-1", sink=sink)
    reporter.begin_run("123456789012", ["us-east-1"], "CASE-1", ["cloudtrail"])
    reporter.start("cloudtrail")
    reporter.event("cloudtrail", "500 records collected", records=500)

    last = sink.matrix_updates[-1]["matrix"]
    row = last["collectors"][0]
    assert row["status"] == "running"
    assert row["records"] == 500
    assert any(e.get("records") == 500 for e in sink.events)


def test_api_reporter_writes_matrix_on_finish() -> None:
    sink = _MemorySink()
    matrix = MatrixState(severity_resolver=lambda _n: "High")
    reporter = ApiReporter(matrix, run_id="run-1", sink=sink)
    reporter.begin_run("123456789012", ["us-east-1"], "CASE-1", ["cloudtrail"])
    reporter.start("cloudtrail")
    reporter.event("cloudtrail", "reading")
    reporter.finish(
        "cloudtrail",
        SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, record_count=10),
    )
    reporter.finalize()

    assert sink.matrix_updates
    last = sink.matrix_updates[-1]["matrix"]
    assert last["total"] == 1
    assert last["collectors"][0]["status"] == "pass"
    assert any(e.get("type") == "finish" for e in sink.events)


def test_late_event_after_cancel_does_not_resurrect_running() -> None:
    """A still-running collector's progress line must not repaint a cancelled row."""
    sink = _MemorySink()
    matrix = MatrixState(severity_resolver=lambda _n: "High")
    cancelled = {"flag": False}
    reporter = ApiReporter(
        matrix,
        run_id="run-1",
        sink=sink,
        cancel_checker=lambda: cancelled["flag"],
    )
    reporter.begin_run("123456789012", ["us-east-1"], "CASE-1", ["cloudtrail", "iam"])
    reporter.start("cloudtrail")

    # Operator cancels while cloudtrail is mid-collection.
    cancelled["flag"] = True
    # …then a late progress event arrives from the still-running collector.
    reporter.event("cloudtrail", "reading page 2")
    # …and the worker eventually drains the run.
    reporter.finalize()

    # No published matrix may ever show the collector "running" carrying the post-cancel
    # message — that resurrection is exactly the bug being guarded against.
    for upd in sink.matrix_updates:
        for r in upd["matrix"]["collectors"]:
            if r["name"] == "cloudtrail":
                assert not (r["status"] == "running" and r.get("live_msg") == "reading page 2")

    last = sink.matrix_updates[-1]["matrix"]
    rows = {r["name"]: r for r in last["collectors"]}
    # Running row is failed with a reason, not "running"/"collecting…"; pending never starts.
    assert rows["cloudtrail"]["status"] == "fail"
    assert rows["cloudtrail"]["live_msg"] == ""
    assert rows["cloudtrail"]["detail"] == "Cancelled while collecting"
    assert rows["iam"]["status"] == "fail"
    assert rows["iam"]["detail"] == "Cancelled before start"
    # The raw log line is still recorded so the per-collector panel reads like a terminal.
    assert any(
        e.get("type") == "event" and e.get("message") == "reading page 2" for e in sink.events
    )


def test_start_after_cancel_is_suppressed() -> None:
    """Once cancelled, a not-yet-started collector must not flip to running."""
    sink = _MemorySink()
    matrix = MatrixState(severity_resolver=lambda _n: "High")
    cancelled = {"flag": True}
    reporter = ApiReporter(
        matrix, run_id="run-1", sink=sink, cancel_checker=lambda: cancelled["flag"]
    )
    reporter.begin_run("123456789012", ["us-east-1"], "CASE-1", ["cloudtrail"])
    reporter.start("cloudtrail")
    reporter.finalize()

    last = sink.matrix_updates[-1]["matrix"]
    assert last["collectors"][0]["status"] == "fail"
    assert not any(e.get("type") == "start" for e in sink.events)


def test_pipeline_steps_publish_live_progress() -> None:
    sink = _MemorySink()
    matrix = MatrixState(severity_resolver=lambda _n: "High")
    reporter = ApiReporter(matrix, run_id="run-1", sink=sink)
    reporter.begin_run(
        "123456789012",
        ["us-east-1"],
        "CASE-1",
        ["cloudtrail"],
        pipeline_steps=["package", "ingest"],
    )
    reporter.finish(
        "cloudtrail",
        SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, record_count=10),
    )
    reporter.start_step("package", "Archiving evidence files…")
    reporter.step_event("package", "Compressing archive (zstd)…")
    reporter.finish_step("package", success=True, detail="1,024 bytes · zstd")
    reporter.start_step("ingest", "Opening evidence package…")
    reporter.step_event("ingest", "100,000 events normalized…")
    reporter.finish_step("ingest", success=True, detail="250,000 events loaded", records=250_000)
    reporter.finalize()

    last = sink.matrix_updates[-1]["matrix"]
    assert last["total"] == 3
    assert last["complete"] == 3
    names = [row["name"] for row in last["collectors"]]
    assert names == ["cloudtrail", "package", "ingest"]
    assert last["collectors"][1]["status"] == "pass"
    assert last["collectors"][2]["records"] == 250_000


def test_raw_log_emits_debug_and_updates_pending_live_msg() -> None:
    sink = _MemorySink()
    matrix = MatrixState(severity_resolver=lambda _n: "High")
    reporter = ApiReporter(matrix, run_id="run-1", sink=sink)
    reporter.begin_run("123456789012", ["us-east-1"], "CASE-1", ["cloud_audit_admin"])
    reporter.raw_log("cloud_audit_admin", "[gcs] table `proj.ds.cloudaudit_googleapis_com_activity`")
    assert any(
        e.get("type") == "debug" and e.get("message", "").startswith("[gcs]")
        for e in sink.events
    )
    row = sink.matrix_updates[-1]["matrix"]["collectors"][0]
    assert row["name"] == "cloud_audit_admin"
    assert row["status"] == "pending"
    assert "[gcs]" in row.get("live_msg", "")
