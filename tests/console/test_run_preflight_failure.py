"""A run that fails in preflight (before begin_run) must still show the collector plan.

Regression for the "Waiting for collector…" / "no events yet" spinner: when identity/DNS/auth
fails before the runner publishes its plan, _seed_failed_plan fills the matrix with the plan
marked failed so the UI renders collectors + the error instead of hanging.
"""

from __future__ import annotations

import collector.engine.run_launcher as run_launcher
from collector.engine.api_reporter import ApiReporter
from collector.engine.matrix_state import MatrixState
from collector.engine.run_launcher import RunLaunchRequest
from console.backend.app import run_service


class _Sink:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.matrices: list[dict] = []
        self.meta: dict = {}

    def update_matrix(self, run_id, matrix):
        self.matrices.append(matrix)

    def append_event(self, run_id, event):
        self.events.append(event)

    def update_meta(self, run_id, patch):
        self.meta.update(patch)
        return patch


def _reporter():
    sink = _Sink()
    return ApiReporter(MatrixState(), run_id="r1", sink=sink), sink


def test_seed_failed_plan_fills_matrix_when_empty(monkeypatch) -> None:
    monkeypatch.setattr(run_launcher, "_resolve_collectors", lambda req: (["alpha", "beta"], [], "aws"))
    monkeypatch.setattr(run_launcher, "_matrix_meta", lambda cloud, refs, root: ("2 artifacts", {}, {}))

    reporter, sink = _reporter()
    req = RunLaunchRequest(cloud="aws", case_id="C-1", artifacts=["alpha", "beta"])

    run_service._seed_failed_plan(reporter, req, "Could not reach the GCP API endpoint …")

    rows = reporter.matrix.snapshot_rows()
    assert [r.name for r in rows] == ["alpha", "beta"]
    assert all(r.status == "fail" for r in rows)  # not left "pending"
    assert all(r.detail for r in rows)
    # a begin_run event was emitted so the run log is no longer empty
    assert any(e.get("type") == "begin_run" for e in sink.events)


def test_seed_failed_plan_is_noop_when_rows_exist(monkeypatch) -> None:
    called = {"n": 0}

    def _boom(req):
        called["n"] += 1
        raise AssertionError("should not resolve when plan already published")

    monkeypatch.setattr(run_launcher, "_resolve_collectors", _boom)

    reporter, _ = _reporter()
    reporter.matrix.begin_run("acct", [], "C", ["already"])  # plan already published
    run_service._seed_failed_plan(reporter, RunLaunchRequest(cloud="aws", case_id="C"), "err")

    assert called["n"] == 0
    assert [r.name for r in reporter.matrix.snapshot_rows()] == ["already"]


def test_seed_failed_plan_swallows_resolution_failure(monkeypatch) -> None:
    # If the plan itself can't be resolved (e.g. the failure WAS a bad artifact selection),
    # seeding is a no-op and must not raise — the error banner still informs the operator.
    def _raise(req):
        raise ValueError("Select at least one artifact.")

    monkeypatch.setattr(run_launcher, "_resolve_collectors", _raise)
    reporter, _ = _reporter()
    run_service._seed_failed_plan(reporter, RunLaunchRequest(cloud="aws", case_id="C"), "err")
    assert reporter.matrix.snapshot_rows() == []
