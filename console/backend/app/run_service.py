"""Background collection orchestration for console POST /api/runs."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

from collector.engine.api_reporter import ApiReporter
from collector.engine.matrix_state import DEFAULT_SEVERITY, MatrixState
from collector.engine.run_launcher import RunLaunchRequest, launch_collection
from collector.lib.ingest import ingest_after_collect

from .config import settings
from .config_store import ConfigNotFound, config_store
from .run_store import run_store


def _severity_for_registry(cloud: str):
    if cloud == "azure":
        from collector.engine.registry import AZURE_REGISTRY as REGISTRY
    elif cloud == "gcp":
        from collector.engine.registry import GCP_REGISTRY as REGISTRY
    else:
        from collector.engine.registry import AWS_REGISTRY as REGISTRY

    def _resolve(name: str) -> str:
        cls = REGISTRY.get(name)
        priority = getattr(cls, "priority", 2) if cls else 2
        return DEFAULT_SEVERITY.get(name, "High" if priority == 1 else "Medium")

    return _resolve


def _apply_connection(req: RunLaunchRequest, connection_id: str | None) -> RunLaunchRequest:
    if not connection_id:
        return req
    conn = config_store.get_connection(connection_id)
    platform = conn.get("platform", req.cloud)
    return RunLaunchRequest(
        cloud=platform or req.cloud,
        case_id=req.case_id,
        artifacts=req.artifacts,
        pack=req.pack,
        regions=req.regions,
        since=req.since,
        until=req.until,
        project=conn.get("project") or req.project,
        subscription=conn.get("subscription") or req.subscription,
        azure_tenant_id=conn.get("azure_tenant_id") or req.azure_tenant_id,
        azure_client_id=conn.get("azure_client_id") or req.azure_client_id,
        aws_profile=conn.get("profile_name") or req.aws_profile,
        max_records_per_source=req.max_records_per_source,
        artifact_parameters=req.artifact_parameters,
        gcp_log_backend=req.gcp_log_backend,
        credentials_path=req.credentials_path,
        out_dir=req.out_dir,
        engagement_id=req.engagement_id,
        key_path=req.key_path,
        reporter=req.reporter,
        artifacts_root=req.artifacts_root,
    )


def _execute_run(run_id: str, body: dict[str, Any]) -> None:
    cloud = body["cloud"]
    case_id = body["case_id"]
    auto_ingest = body.get("auto_ingest", True)
    connection_id = body.get("connection_id")

    matrix = MatrixState(severity_resolver=_severity_for_registry(cloud))
    reporter = ApiReporter(matrix, run_id=run_id, sink=run_store)

    req = RunLaunchRequest(
        cloud=cloud,
        case_id=case_id,
        artifacts=list(body.get("artifacts") or []),
        pack=body.get("pack"),
        regions=body.get("regions") or None,
        since=body.get("since") or "",
        until=body.get("until") or "",
        project=body.get("project") or "",
        subscription=body.get("subscription") or "",
        azure_tenant_id=body.get("azure_tenant_id") or "",
        azure_client_id=body.get("azure_client_id") or "",
        aws_profile=body.get("aws_profile") or "",
        max_records_per_source=body.get("max_records_per_source"),
        artifact_parameters=body.get("artifact_parameters") or {},
        gcp_log_backend=body.get("gcp_log_backend"),
        artifacts_root=settings.artifacts_root,
        reporter=reporter,
    )
    try:
        req = _apply_connection(req, connection_id)
    except ConfigNotFound as exc:
        run_store.finalize(run_id, status="failed", error=str(exc))
        return

    try:
        package = launch_collection(req)
    except Exception as exc:  # noqa: BLE001
        reporter.finalize()
        run_store.finalize(run_id, status="failed", error=str(exc))
        run_store.append_event(run_id, {"type": "error", "message": str(exc)})
        return

    reporter.finalize()
    extra: dict[str, Any] = {
        "package": {
            "path": str(package.path),
            "compression": package.compression,
            "bytes": package.bytes,
            "sha256": package.sha256,
        },
        "collectors": reporter.collectors_report(),
        "coverage_gaps": reporter.coverage_gaps(),
    }

    ingest_result: dict[str, Any] | None = None
    if auto_ingest:
        try:
            from ventra_ingester.pipeline import ingest_package

            result = ingest_package(package.path, settings.case_store)
            ingest_result = {
                "case_id": result.case_id,
                "events": result.event_count,
                "integrity": result.integrity_overall,
                "warnings": result.warnings,
            }
            extra["ingest"] = ingest_result
            run_store.append_event(run_id, {"type": "ingested", **ingest_result})
        except Exception as exc:  # noqa: BLE001
            extra["ingest_error"] = str(exc)
            run_store.append_event(run_id, {"type": "ingest_error", "message": str(exc)})

    run_store.finalize(run_id, status="completed", extra=extra)
    run_store.append_event(run_id, {"type": "completed"})


_active_runs: set[str] = set()
_active_lock = threading.Lock()


def start_run(body: dict[str, Any]) -> dict[str, Any]:
    """Create run record and schedule background execution."""
    meta = {
        "cloud": body["cloud"],
        "case_id": body["case_id"],
        "connection_id": body.get("connection_id"),
        "auto_ingest": body.get("auto_ingest", True),
        "request": {k: v for k, v in body.items() if k != "auto_ingest"},
    }
    record = run_store.create_run(meta)
    run_id = record["run_id"]

    def _runner() -> None:
        with _active_lock:
            _active_runs.add(run_id)
        try:
            _execute_run(run_id, body)
        finally:
            with _active_lock:
                _active_runs.discard(run_id)

    thread = threading.Thread(target=_runner, name=f"ventra-run-{run_id}", daemon=True)
    thread.start()
    return record


async def start_run_async(body: dict[str, Any]) -> dict[str, Any]:
    """Async wrapper that offloads thread startup."""
    return await asyncio.to_thread(start_run, body)


def test_connection(connection_id: str) -> dict[str, Any]:
    """Best-effort identity check for a saved connection."""
    conn = config_store.get_connection(connection_id)
    platform = (conn.get("platform") or "").strip().lower()
    try:
        if platform == "aws":
            import boto3

            profile = conn.get("profile_name") or None
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            ident = session.client("sts").get_caller_identity()
            return {
                "ok": True,
                "platform": platform,
                "account_id": ident.get("Account"),
                "arn": ident.get("Arn"),
            }
        if platform in {"azure", "m365"}:
            from collector.clouds.azure.client_factory import AzureClientFactory
            from collector.lib.auth import azure_factory_kwargs
            from collector.lib.models import AzureAuthOptions

            auth = AzureAuthOptions(
                tenant_id=conn.get("azure_tenant_id") or "",
                client_id=conn.get("azure_client_id") or "",
            )
            factory = AzureClientFactory(
                **azure_factory_kwargs(auth, subscription_id=conn.get("subscription") or None)
            )
            ident = factory.caller_identity()
            return {
                "ok": True,
                "platform": platform,
                "tenant_id": ident.tenant_id,
                "principal": ident.principal,
            }
        if platform == "gcp":
            from collector.clouds.gcp.client_factory import GcpClientFactory

            factory = GcpClientFactory(project_id=conn.get("project") or None)
            ident = factory.caller_identity()
            return {
                "ok": True,
                "platform": platform,
                "project_id": ident.project_id,
                "principal": ident.principal,
            }
        return {"ok": False, "error": f"Unsupported platform: {platform}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "platform": platform, "error": str(exc)}

def apply_relay_payload(run_id: str, payload: dict[str, Any]) -> None:
    """Apply matrix/event/meta updates posted by a Cloud Shell kit relay."""
    typ = payload.get("type")
    if typ == "matrix":
        run_store.update_matrix(run_id, payload.get("matrix") or {})
    elif typ == "event":
        run_store.append_event(run_id, payload.get("event") or {})
    elif typ == "meta":
        run_store.update_meta(run_id, payload.get("meta") or {})
    else:
        run_store.append_event(run_id, payload)

