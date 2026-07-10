"""File-backed run store — JSON metadata + matrix snapshots + event log."""

from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


class RunNotFound(Exception):
    pass


class RunStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _run_dir(self, run_id: str) -> Path:
        return self.root / run_id

    def create_run(self, meta: dict[str, Any]) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "run_id": run_id,
            "status": "pending",
            "created_at": _now_iso(),
            "started_at": None,
            "finished_at": None,
            **meta,
        }
        self._write_json(run_dir / "meta.json", entry)
        self._write_json(run_dir / "matrix.json", {"collectors": [], "complete": 0, "total": 0})
        (run_dir / "events.jsonl").touch()
        return entry

    def list_runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        if not self.root.is_dir():
            return runs
        for path in sorted(self.root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_dir():
                continue
            meta_path = path / "meta.json"
            if meta_path.is_file():
                runs.append(json.loads(meta_path.read_text(encoding="utf-8")))
        return runs

    def get_run(self, run_id: str) -> dict[str, Any]:
        meta_path = self._run_dir(run_id) / "meta.json"
        if not meta_path.is_file():
            raise RunNotFound(run_id)
        return json.loads(meta_path.read_text(encoding="utf-8"))

    def get_matrix(self, run_id: str) -> dict[str, Any]:
        path = self._run_dir(run_id) / "matrix.json"
        if not path.is_file():
            raise RunNotFound(run_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def update_matrix(self, run_id: str, snapshot: dict[str, Any]) -> None:
        with self._lock:
            self._write_json(self._run_dir(run_id) / "matrix.json", snapshot)

    def update_meta(self, run_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            meta = self.get_run(run_id)
            meta.update(patch)
            self._write_json(self._run_dir(run_id) / "meta.json", meta)
            return meta

    def mark_started(self, run_id: str) -> None:
        """Stamp when execution actually begins so elapsed/duration measure real run time."""
        with self._lock:
            meta = self.get_run(run_id)
            patch: dict[str, Any] = {"status": "running"}
            if not meta.get("started_at"):
                patch["started_at"] = _now_iso()
            meta.update(patch)
            self._write_json(self._run_dir(run_id) / "meta.json", meta)

    def append_event(self, run_id: str, event: dict[str, Any]) -> None:
        line = json.dumps({**event, "ts": _now_iso()})
        with self._lock:
            run_dir = self._run_dir(run_id)
            if not run_dir.is_dir():
                raise RunNotFound(run_id)
            with (run_dir / "events.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def finalize(
        self,
        run_id: str,
        *,
        status: str,
        error: str | None = None,
        package_path: str | None = None,
        ingested: bool | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        finished = _now_iso()
        patch: dict[str, Any] = {
            "status": status,
            "finished_at": finished,
        }
        try:
            meta = self.get_run(run_id)
            base = meta.get("started_at") or meta.get("created_at")
            if base:
                delta = datetime.fromisoformat(finished) - datetime.fromisoformat(base)
                patch["duration_ms"] = max(0, int(delta.total_seconds() * 1000))
        except Exception:  # noqa: BLE001 — duration is best-effort display metadata
            pass
        if error:
            patch["error"] = error
        if package_path:
            patch["package_path"] = package_path
        if ingested is not None:
            patch["ingested"] = ingested
        if extra:
            patch.update(extra)
        return self.update_meta(run_id, patch)

    def iter_events(self, run_id: str, *, after: int = 0) -> Iterator[dict[str, Any]]:
        path = self._run_dir(run_id) / "events.jsonl"
        if not path.is_file():
            raise RunNotFound(run_id)
        with path.open(encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if i < after:
                    continue
                line = line.strip()
                if line:
                    yield json.loads(line)

    def read_events(self, run_id: str) -> list[dict[str, Any]]:
        return list(self.iter_events(run_id))

    def read_events_since(self, run_id: str, offset: int) -> list[dict[str, Any]]:
        return list(self.iter_events(run_id, after=offset))

    def request_cancel(self, run_id: str) -> dict[str, Any]:
        """Flag a run for cancellation and repaint the matrix immediately.

        The worker thread owns finalization, so this never marks the run terminal — it
        moves an active run to the transient ``cancelling`` state and folds the cancel into
        the matrix so the UI updates instantly, even while the in-flight collector is still
        wrapping up. ``cancel_requested`` is what the reporter's ``should_cancel()`` reads.
        """
        patch: dict[str, Any] = {
            "cancel_requested": True,
            "cancel_requested_at": _now_iso(),
        }
        meta = self.get_run(run_id)
        if str(meta.get("status") or "") in {"pending", "running"}:
            patch["status"] = "cancelling"
        result = self.update_meta(run_id, patch)
        try:
            matrix = self.get_matrix(run_id)
            self._apply_cancel_to_matrix(matrix, status="cancelling")
            self.update_matrix(run_id, matrix)
            self.append_event(
                run_id,
                {"type": "cancelling", "message": "Cancelling — stopping collectors…"},
            )
        except RunNotFound:
            pass
        return result

    @staticmethod
    def _apply_cancel_to_matrix(matrix: dict[str, Any], *, status: str = "cancelled") -> dict[str, Any]:
        """Mark non-terminal collectors failed with a reason so the UI reflects cancellation.

        Running rows are flagged as interrupted mid-collection and pending rows as never
        started, so the analyst can see *where* the run stopped. Idempotent — terminal rows
        are left as-is.
        """
        collectors = matrix.get("collectors") or []
        for row in collectors:
            st = str(row.get("status") or "").lower()
            if st == "running":
                row["status"] = "fail"
                row["detail"] = "Cancelled while collecting"
                row["live_msg"] = ""
            elif st == "pending":
                row["status"] = "fail"
                row["detail"] = "Cancelled before start"
                row["live_msg"] = ""
        done = sum(
            1
            for row in collectors
            if str(row.get("status") or "").lower() in {"pass", "fail", "partial"}
        )
        matrix["complete"] = done
        matrix["total"] = matrix.get("total") or len(collectors)
        matrix["status"] = status
        return matrix

    @staticmethod
    def _write_json(path: Path, data: dict[str, Any]) -> None:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


from .config import settings

run_store = RunStore(settings.runs_dir)
