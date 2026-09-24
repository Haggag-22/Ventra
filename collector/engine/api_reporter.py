"""RunReporter that persists matrix snapshots to the console run store or relay URL."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from ..lib.models import GapReason, SourceResult, SourceStatus
from .matrix_state import MatrixState
from .run_common import RunReporter

# Distinct cancel reasons so the console can show where a run was interrupted.
CANCEL_RUNNING_DETAIL = "Cancelled while collecting"
CANCEL_PENDING_DETAIL = "Cancelled before start"


class RunSink(Protocol):
    def update_matrix(self, run_id: str, matrix: dict[str, Any]) -> None: ...

    def append_event(self, run_id: str, event: dict[str, Any]) -> None: ...

    def update_meta(self, run_id: str, patch: dict[str, Any]) -> dict[str, Any]: ...


class _HttpRelaySink:
    """POST matrix/event payloads to a console relay endpoint (Cloud Shell kit mode)."""

    def __init__(self, relay_url: str) -> None:
        self.relay_url = relay_url.rstrip("/")

    def _post(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.relay_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                resp.read()
        except urllib.error.URLError:
            pass

    def update_matrix(self, run_id: str, matrix: dict[str, Any]) -> None:
        del run_id
        self._post({"type": "matrix", "matrix": matrix})

    def append_event(self, run_id: str, event: dict[str, Any]) -> None:
        del run_id
        self._post({"type": "event", "event": event})

    def update_meta(self, run_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        del run_id
        self._post({"type": "meta", "meta": patch})
        return patch


class ApiReporter(RunReporter):
    """Write matrix state changes to a run store or HTTP relay on every update."""

    def __init__(
        self,
        matrix: MatrixState,
        *,
        run_id: str,
        sink: RunSink | None = None,
        relay_url: str | None = None,
        cancel_checker: Callable[[], bool] | None = None,
    ) -> None:
        super().__init__()
        self.matrix = matrix
        self.run_id = run_id
        self._cancel_checker = cancel_checker or (lambda: False)
        if sink is not None:
            self._sink = sink
        elif relay_url:
            self._sink = _HttpRelaySink(relay_url)
        else:
            raise ValueError("ApiReporter requires sink or relay_url")

    def should_cancel(self) -> bool:
        return self._cancel_checker()

    def abort_remaining(self, detail: str = "Cancelled") -> None:
        self.matrix.abort_non_terminal(
            detail=detail,
            running_detail=CANCEL_RUNNING_DETAIL,
            pending_detail=CANCEL_PENDING_DETAIL,
        )
        self._publish_matrix()
        self._sink.append_event(self.run_id, {"type": "cancelled", "message": detail})

    def _publish_matrix(self) -> None:
        # Once a cancel is in flight, fold the abort into every publish. This is the single
        # guard that stops a still-running collector's late progress event from resurrecting
        # a "running/collecting…" row after the operator has cancelled.
        if self.should_cancel():
            self.matrix.abort_non_terminal(
                running_detail=CANCEL_RUNNING_DETAIL,
                pending_detail=CANCEL_PENDING_DETAIL,
            )
        done, total = self.matrix.progress()
        snap = self.matrix.snapshot()
        payload = {
            **snap,
            "collectors": snap["collectors"],
            "complete": done,
            "total": total,
        }
        self._sink.update_matrix(self.run_id, payload)

    def _log_event(self, event_type: str, **fields: Any) -> None:
        self._sink.append_event(self.run_id, {"type": event_type, **fields})
        if event_type in {"start", "finish", "begin_run"}:
            self._publish_matrix()

    def begin_run(
        self,
        account_id: str,
        regions: list[str],
        case_id: str = "",
        collectors: list[str] | None = None,
        *,
        plan_label: str = "",
        artifact_labels: dict[str, str] | None = None,
        artifact_severities: dict[str, str] | None = None,
        preflight_lines: list[str] | None = None,
        pipeline_steps: list[str] | None = None,
    ) -> None:
        self.matrix.begin_run(
            account_id,
            regions,
            case_id,
            collectors,
            plan_label=plan_label,
            artifact_labels=artifact_labels,
            artifact_severities=artifact_severities,
            pipeline_steps=pipeline_steps,
        )
        self._sink.update_meta(
            self.run_id,
            {
                "account_id": account_id,
                "masked_account": self.matrix.masked_account,
                "regions": regions,
                "plan_label": plan_label,
                "status": "running",
            },
        )
        self._log_event(
            "begin_run",
            account_id=account_id,
            regions=regions,
            case_id=case_id,
            collectors=collectors or [],
            plan_label=plan_label,
            preflight_lines=preflight_lines or [],
        )

    def start(self, name: str) -> None:
        # After a cancel, don't flip a not-yet-started collector to running/collecting.
        if self.should_cancel():
            return
        self.events.append((name, "running"))
        self.matrix.start(name)
        self._log_event("start", collector=name)

    def event(self, name: str, msg: str, records: int | None = None) -> None:
        super().event(name, msg, records=records)
        # Always surface the raw line so the per-collector panel reads like a terminal…
        payload: dict[str, Any] = {"type": "event", "collector": name, "message": msg}
        if isinstance(records, int):
            payload["records"] = records
        self._sink.append_event(self.run_id, payload)
        # …but never let a late progress line repaint a "collecting…" state post-cancel.
        if self.should_cancel():
            return
        self.matrix.event(name, msg, records=records)
        self._publish_matrix()

    def raw_log(self, collector: str, message: str) -> None:
        """Emit a verbose debug line to the run log and optional collector live status."""
        super().raw_log(collector, message)
        self._sink.append_event(
            self.run_id,
            {"type": "debug", "collector": collector, "message": message},
        )
        if self.should_cancel():
            return
        if collector not in ("export_bulk", "run", "strategy_resolver"):
            self.matrix.event(collector, message)
        self._publish_matrix()

    def start_step(self, name: str, msg: str = "") -> None:
        if self.should_cancel():
            return
        self.matrix.start_step(name, msg)
        self._log_event("start", collector=name)
        if msg:
            self._sink.append_event(self.run_id, {"type": "event", "collector": name, "message": msg})

    def step_event(self, name: str, msg: str) -> None:
        super().step_event(name, msg)
        self._sink.append_event(self.run_id, {"type": "event", "collector": name, "message": msg})
        if self.should_cancel():
            return
        self.matrix.event(name, msg)
        self._publish_matrix()

    def finish_step(
        self,
        name: str,
        *,
        success: bool,
        detail: str,
        records: int | None = None,
    ) -> None:
        self.matrix.finish_step(name, success=success, detail=detail, records=records)
        self._log_event(
            "finish",
            collector=name,
            status="collected" if success else "failed",
            records=records,
            message=detail,
        )

    def finish(self, name: str, result: SourceResult) -> None:
        if self.should_cancel():
            result = SourceResult(
                name=name,
                status=SourceStatus.SKIPPED,
                gaps=[(name, GapReason.COLLECTOR_ERROR, CANCEL_RUNNING_DETAIL)],
                notes=CANCEL_RUNNING_DETAIL,
            )
        self.matrix.finish(name, result)
        self.events.append((name, result.status.value))
        self._log_event(
            "finish",
            collector=name,
            status=result.status.value,
            records=result.record_count,
        )

    def finalize(self) -> None:
        self._publish_matrix()

    def stop(self) -> None:
        pass

    def coverage_gaps(self) -> list[dict]:
        return self.matrix.coverage_gaps()

    def rate_limited_collectors(self) -> list[str]:
        return self.matrix.rate_limited_collectors()

    def collectors_report(self) -> list[dict]:
        return self.matrix.collectors_report()

    @property
    def rows(self) -> list[dict]:
        return self.matrix.finished_csv_rows

    @property
    def _account(self) -> str:
        return self.matrix.account_id

    def write_matrix_csv(self, out_dir) -> Any:
        import csv
        from pathlib import Path

        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "collection_matrix.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["status", "account", "scope", "check", "severity", "records", "elapsed_s", "detail"])
            for r in self.matrix.finished_csv_rows:
                w.writerow(
                    [
                        r["label"],
                        self.matrix.account_id,
                        r["scope"],
                        r["check"],
                        r["severity"],
                        r["tag"],
                        r["elapsed"],
                        r["desc"],
                    ]
                )
        return path
