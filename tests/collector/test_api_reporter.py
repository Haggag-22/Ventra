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
