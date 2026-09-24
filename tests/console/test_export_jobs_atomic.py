"""Export job records must never be observed half-written while a job is being updated."""

from __future__ import annotations

import sys
import threading
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "backend"))

from app import export_jobs  # noqa: E402


def test_status_polls_never_see_a_partial_record() -> None:
    job_id = f"test-{uuid.uuid4().hex}"
    export_jobs._write_job({"job_id": job_id, "status": "pending", "padding": "x" * 200_000})
    stop = threading.Event()

    def writer() -> None:
        n = 0
        while not stop.is_set():
            n += 1
            export_jobs._update_job(job_id, {"status": "running", "n": n})

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        misses = sum(export_jobs.get_export_job(job_id) is None for _ in range(3000))
    finally:
        stop.set()
        t.join(timeout=5)
        export_jobs._job_file(job_id).unlink(missing_ok=True)
    assert misses == 0, f"{misses} polls saw a missing/partial job record"


def test_concurrent_updates_are_not_lost() -> None:
    job_id = f"test-{uuid.uuid4().hex}"
    export_jobs._write_job({"job_id": job_id, "status": "pending"})
    keys = [f"k{i}" for i in range(8)]

    def bump(key: str) -> None:
        for _ in range(50):
            export_jobs._update_job(job_id, {key: True})

    threads = [threading.Thread(target=bump, args=(k,)) for k in keys]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    try:
        rec = export_jobs.get_export_job(job_id)
        assert rec is not None
        assert all(rec.get(k) for k in keys), "an update from another thread was overwritten"
    finally:
        export_jobs._job_file(job_id).unlink(missing_ok=True)
