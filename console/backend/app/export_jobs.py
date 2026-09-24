"""Subprocess workers for SIEM export.

Large cases (millions of events) spend a long time in DuckDB + Python JSON serialization.
Running that work in a child process keeps the uvicorn worker's GIL free so /api/health,
/api/cases/exportable, and the rest of the console stay responsive during an export.

Two deliveries share the same NDJSON build:

* ``download`` — zip the files and let the browser download them.
* ``drop_zone`` — write NDJSON into ``VENTRA_EXPORT_DROP_DIR`` for a client forwarder
  (Logstash / Filebeat / Splunk UF). Ventra never POSTs to a SIEM.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import shutil
import threading
import time
import traceback
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _zip_dir(out_dir: Path, zip_path: Path, *, arc_prefix: str = "") -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(out_dir.rglob("*")):
            if path.is_file():
                rel = path.relative_to(out_dir).as_posix()
                zf.write(path, arcname=f"{arc_prefix}{rel}" if arc_prefix else rel)


def build_single_case_export_dir(
    *,
    case_dir: str,
    out_dir: str,
    target: str = "elastic",
    sources: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    """Write one case export (NDJSON + manifest) into ``out_dir``. Returns the manifest."""
    from ventra_ingester.exporters.elastic_ndjson import export_ndjson

    dest = Path(out_dir)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    export_ndjson(
        Path(case_dir),
        dest,
        target=target,
        sources=sources,
        since=since,
        until=until,
    )
    return json.loads((dest / "export-manifest.json").read_text(encoding="utf-8"))


def build_batch_export_dir(
    *,
    case_dirs: dict[str, str],
    out_dir: str,
    target: str,
    sources: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    """Write one or more cases into ``out_dir``.

    Single case: flat layout (``*.ndjson`` + ``export-manifest.json``).
    Multiple cases: per-case subfolders + top-level ``export-manifest.json``.
    """
    case_ids = list(case_dirs.keys())
    if len(case_ids) == 1:
        return build_single_case_export_dir(
            case_dir=case_dirs[case_ids[0]],
            out_dir=out_dir,
            target=target,
            sources=sources,
            since=since,
            until=until,
        )

    from ventra_ingester.exporters.elastic_ndjson import export_ndjson

    dest = Path(out_dir)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    combined: dict[str, Any] = {"target": target, "cases": []}
    for case_id in case_ids:
        case_out = dest / case_id
        export_ndjson(
            Path(case_dirs[case_id]),
            case_out,
            target=target,
            sources=sources,
            since=since,
            until=until,
        )
        manifest = json.loads((case_out / "export-manifest.json").read_text(encoding="utf-8"))
        combined["cases"].append(
            {
                "case_id": case_id,
                "sources": manifest["sources"],
                "total_events": manifest["total_events"],
            }
        )
    combined["total_events"] = sum(c["total_events"] for c in combined["cases"])
    if sources:
        combined["source_filter"] = sorted(sources)
    if since:
        combined["since"] = since
    if until:
        combined["until"] = until
    (dest / "export-manifest.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")
    return combined


def build_single_case_export_zip(
    *,
    case_dir: str,
    zip_path: str,
    target: str = "elastic",
    sources: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> None:
    """Write one case export zip to ``zip_path`` (parent dirs must exist)."""
    tmp_out = Path(zip_path).parent / "export"
    build_single_case_export_dir(
        case_dir=case_dir,
        out_dir=str(tmp_out),
        target=target,
        sources=sources,
        since=since,
        until=until,
    )
    _zip_dir(tmp_out, Path(zip_path))


def build_batch_export_zip(
    *,
    case_dirs: dict[str, str],
    zip_path: str,
    target: str,
    sources: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> None:
    """Write a multi-case export zip (per-case subfolders + top-level manifest)."""
    case_ids = list(case_dirs.keys())
    if len(case_ids) == 1:
        build_single_case_export_zip(
            case_dir=case_dirs[case_ids[0]],
            zip_path=zip_path,
            target=target,
            sources=sources,
            since=since,
            until=until,
        )
        return

    zip_file = Path(zip_path)
    work = zip_file.parent / "export"
    build_batch_export_dir(
        case_dirs=case_dirs,
        out_dir=str(work),
        target=target,
        sources=sources,
        since=since,
        until=until,
    )
    _zip_dir(work, zip_file)


def drop_export_dirname(*, case_ids: list[str], target: str, job_id: str) -> str:
    """Stable, unique folder name under the drop zone."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    short = job_id[:8]
    if len(case_ids) == 1:
        safe = case_ids[0].replace("/", "_").replace(" ", "_")
        return f"{stamp}-{safe}-{target}-{short}"
    return f"{stamp}-ventra-export-{target}-{len(case_ids)}-cases-{short}"


def build_drop_zone_export(
    *,
    case_dirs: dict[str, str],
    drop_root: str,
    export_name: str,
    target: str,
    sources: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    """Build NDJSON into a staging folder under ``drop_root``, then atomically rename.

    Returns ``{"drop_path": str, "manifest": dict}``. Staging uses a ``.partial-`` prefix so
    forwarders watching the drop zone do not ingest half-written files.
    """
    root = Path(drop_root)
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f".partial-{export_name}"
    final = root / export_name
    if staging.exists():
        shutil.rmtree(staging)
    if final.exists():
        shutil.rmtree(final)

    try:
        manifest = build_batch_export_dir(
            case_dirs=case_dirs,
            out_dir=str(staging),
            target=target,
            sources=sources,
            since=since,
            until=until,
        )
        staging.rename(final)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return {"drop_path": str(final.resolve()), "manifest": manifest}


def _worker_single(q: mp.Queue, kwargs: dict[str, Any]) -> None:
    try:
        build_single_case_export_zip(**kwargs)
        q.put(("ok", None))
    except Exception as exc:  # noqa: BLE001
        q.put(("err", f"{exc}\n{traceback.format_exc()}"))


def _worker_batch(q: mp.Queue, kwargs: dict[str, Any]) -> None:
    try:
        build_batch_export_zip(**kwargs)
        q.put(("ok", None))
    except Exception as exc:  # noqa: BLE001
        q.put(("err", f"{exc}\n{traceback.format_exc()}"))


def _worker_drop(q: mp.Queue, kwargs: dict[str, Any]) -> None:
    try:
        result = build_drop_zone_export(**kwargs)
        q.put(("ok", result))
    except Exception as exc:  # noqa: BLE001
        q.put(("err", f"{exc}\n{traceback.format_exc()}"))


# -- async export jobs -------------------------------------------------------------------
#
# Large cases (millions of events) take minutes to serialize. Building the zip inside the
# request meant the HTTP response sent zero bytes for the whole build, so the dev proxy /
# client reset the connection long before the zip was ready. Jobs decouple the build from
# the request: POST starts a job and returns immediately, the client polls, then downloads
# the finished zip (or reads drop_path for drop-zone delivery).

# Job state is kept on disk (not in a per-worker dict) so status/download survive a uvicorn
# --reload worker restart and work no matter which worker handles the poll. Each job is a
# small JSON file; the built zip / drop folder live under their own paths recorded in it.
# Live Process handles stay in-memory so Cancel can terminate the child.

_jobs_lock = threading.Lock()
_procs_lock = threading.Lock()
_active_procs: dict[str, Any] = {}


class ExportCancelled(Exception):
    """Raised when an export job is cancelled while the child process is still running."""


def _jobs_dir() -> Path:
    import tempfile

    d = Path(tempfile.gettempdir()) / "ventra-export-jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _job_file(job_id: str) -> Path:
    return _jobs_dir() / f"{job_id}.json"


def _write_job(record: dict[str, Any]) -> None:
    with _jobs_lock:
        _job_file(record["job_id"]).write_text(json.dumps(record), encoding="utf-8")


def _update_job(job_id: str, patch: dict[str, Any]) -> None:
    rec = get_export_job(job_id)
    if rec is None:
        return
    rec.update(patch)
    _write_job(rec)


def _terminate_proc(proc: Any) -> None:
    if proc is None or not proc.is_alive():
        return
    proc.terminate()
    proc.join(timeout=5)
    if proc.is_alive():
        proc.kill()
        proc.join(timeout=2)


def create_export_job(
    kind: str,
    kwargs: dict[str, Any],
    *,
    tmp_dir: str | None = None,
    zip_path: str | None = None,
    filename: str | None = None,
    delivery: str = "download",
    job_id: str | None = None,
) -> str:
    """Start an export build in a background thread and return its job id immediately."""
    job_id = job_id or uuid.uuid4().hex
    _write_job(
        {
            "job_id": job_id,
            "status": "pending",
            "delivery": delivery,
            "zip_path": zip_path,
            "filename": filename,
            "tmp_dir": tmp_dir,
            "drop_path": None,
            "total_events": None,
            "error": None,
            "cancel_requested": False,
            "created_at": time.time(),
        }
    )

    def _run() -> None:
        _update_job(job_id, {"status": "running"})
        try:
            result = run_export_in_subprocess(kind, kwargs, job_id=job_id)
            job = get_export_job(job_id)
            if job and (job.get("cancel_requested") or job.get("status") == "cancelled"):
                if tmp_dir:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                return
            patch: dict[str, Any] = {"status": "ready"}
            if isinstance(result, dict):
                patch["drop_path"] = result.get("drop_path")
                patch["total_events"] = (result.get("manifest") or {}).get("total_events")
            _update_job(job_id, patch)
        except ExportCancelled:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            _update_job(job_id, {"status": "cancelled", "error": None})
        except Exception as exc:  # noqa: BLE001
            job = get_export_job(job_id)
            if job and (job.get("cancel_requested") or job.get("status") == "cancelled"):
                if tmp_dir:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                return
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            _update_job(job_id, {"status": "error", "error": str(exc)})

    threading.Thread(target=_run, name=f"ventra-export-{job_id}", daemon=True).start()
    return job_id


def get_export_job(job_id: str) -> dict[str, Any] | None:
    path = _job_file(job_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def discard_export_job(job_id: str) -> None:
    """Forget a job (call after its zip has been handed to the download response)."""
    with _procs_lock:
        _active_procs.pop(job_id, None)
    try:
        _job_file(job_id).unlink(missing_ok=True)
    except OSError:
        pass


def cancel_export_job(job_id: str) -> dict[str, Any]:
    """Request cancel, kill the export child if running, and clean staging files."""
    job = get_export_job(job_id)
    if job is None:
        raise KeyError(job_id)
    status = job.get("status")
    if status in ("ready", "error", "cancelled"):
        return job

    _update_job(job_id, {"status": "cancelled", "cancel_requested": True, "error": None})
    with _procs_lock:
        proc = _active_procs.pop(job_id, None)
    _terminate_proc(proc)

    tmp = job.get("tmp_dir")
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    refreshed = get_export_job(job_id)
    return refreshed or {**job, "status": "cancelled", "cancel_requested": True}


def run_export_in_subprocess(kind: str, kwargs: dict[str, Any], *, job_id: str | None = None) -> Any:
    """Run export in a child process; raise RuntimeError with the child traceback on failure.

    Returns the child payload on success (``None`` for zip builds, a result dict for drop).
    Raises ``ExportCancelled`` if the job is cancelled while waiting.
    """
    import queue as queue_mod

    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    if kind == "single":
        target = _worker_single
    elif kind == "batch":
        target = _worker_batch
    elif kind == "drop":
        target = _worker_drop
    else:
        raise ValueError(f"Unknown export kind {kind!r}")
    proc = ctx.Process(target=target, args=(q, kwargs))
    proc.start()
    if job_id:
        with _procs_lock:
            _active_procs[job_id] = proc
    status: str | None = None
    detail: Any = None
    try:
        while True:
            if job_id:
                job = get_export_job(job_id)
                if job and (job.get("cancel_requested") or job.get("status") == "cancelled"):
                    _terminate_proc(proc)
                    raise ExportCancelled(job_id)
            try:
                status, detail = q.get(timeout=0.5)
                break
            except queue_mod.Empty:
                if not proc.is_alive():
                    break
        proc.join(timeout=5)
        if job_id:
            job = get_export_job(job_id)
            if job and (job.get("cancel_requested") or job.get("status") == "cancelled"):
                raise ExportCancelled(job_id)
        if status is None:
            raise RuntimeError(f"export subprocess exited with code {proc.exitcode} before reporting status")
        if status != "ok":
            raise RuntimeError(detail or "export subprocess failed")
        if proc.exitcode not in (0, None):
            raise RuntimeError(f"export subprocess exited with code {proc.exitcode}")
        return detail
    finally:
        if job_id:
            with _procs_lock:
                _active_procs.pop(job_id, None)
