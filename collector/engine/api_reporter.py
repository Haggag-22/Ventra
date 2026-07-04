"""RunReporter that persists matrix snapshots to the console run store or relay URL."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol

from ..lib.models import SourceResult
from .matrix_state import MatrixState
from .run_common import RunReporter


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
    ) -> None:
        super().__init__()
        self.matrix = matrix
        self.run_id = run_id
        if sink is not None:
            self._sink = sink
        elif relay_url:
            self._sink = _HttpRelaySink(relay_url)
        else:
            raise ValueError("ApiReporter requires sink or relay_url")

    def _publish_matrix(self) -> None:
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
        if event_type in {"start", "finish", "event", "begin_run"}:
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
    ) -> None:
        self.matrix.begin_run(
            account_id,
            regions,
            case_id,
            collectors,
            plan_label=plan_label,
            artifact_labels=artifact_labels,
            artifact_severities=artifact_severities,
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
        self.events.append((name, "running"))
        self.matrix.start(name)
        self._log_event("start", collector=name)

    def event(self, name: str, msg: str) -> None:
        super().event(name, msg)
        self.matrix.event(name, msg)
        self._log_event("event", collector=name, message=msg)

    def finish(self, name: str, result: SourceResult) -> None:
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
            w.writerow(
                ["status", "account", "scope", "check", "severity", "records", "elapsed_s", "detail"]
            )
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
