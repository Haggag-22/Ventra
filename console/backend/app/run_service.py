"""Background collection orchestration for console POST /api/runs."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any

from collector.engine.api_reporter import ApiReporter
from collector.engine.matrix_state import DEFAULT_SEVERITY, MatrixState
from collector.engine.run_launcher import RunLaunchRequest, launch_collection
from collector.lib.ingest import ingest_after_collect

from .config import settings
from .config_store import ConfigNotFound, config_store
from .run_store import RunNotFound, run_store

_TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _severity_for_registry(cloud: str):
    if cloud in {"azure", "m365"}:
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


def _aws_session_from_connection(conn: dict[str, Any]):
    """Build a boto3 session from a saved AWS connection record."""
    import boto3

    auth_method = (conn.get("auth_method") or "").strip().lower()
    access_key = (conn.get("aws_access_key_id") or "").strip()
    secret_key = (conn.get("aws_secret_access_key") or "").strip()
    session_token = (conn.get("aws_session_token") or "").strip()
    if auth_method == "credentials" and access_key and secret_key:
        session_kwargs: dict[str, str] = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
        }
        if session_token:
            session_kwargs["aws_session_token"] = session_token
        return boto3.Session(**session_kwargs)

    profile = conn.get("profile_name") or None
    role_arn = (conn.get("role_arn") or "").strip()
    if auth_method == "assume_role" and role_arn:
        base = boto3.Session(profile_name=profile) if profile else boto3.Session()
        creds = base.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName="ventra-connection-test",
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def _aws_credentials_from_connection(conn: dict[str, Any]) -> dict[str, str]:
    """Resolve static credential kwargs from a connection for collection runs."""
    session = _aws_session_from_connection(conn)
    frozen = session.get_credentials()
    if frozen is None:
        return {}
    return {
        "aws_access_key_id": frozen.access_key or "",
        "aws_secret_access_key": frozen.secret_key or "",
        "aws_session_token": frozen.token or "",
    }


_GCP_SA_REQUIRED = ("type", "project_id", "private_key", "client_email")


def parse_gcp_service_account_json(raw: str) -> dict[str, Any]:
    """Parse and validate a GCP service account key JSON string."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Service account key must be valid JSON.") from exc
    if not isinstance(data, dict):
        raise ValueError("Service account key must be a JSON object.")
    if data.get("type") != "service_account":
        raise ValueError('JSON must be a GCP service account key (type: "service_account").')
    missing = [k for k in _GCP_SA_REQUIRED if not str(data.get(k) or "").strip()]
    if missing:
        raise ValueError(f"Service account JSON missing required fields: {', '.join(missing)}")
    return data


def parse_kubeconfig_yaml(raw: str) -> dict[str, Any]:
    """Parse and validate kubeconfig YAML content."""
    import yaml

    text = (raw or "").strip()
    if not text:
        raise ValueError("Kubeconfig content is required.")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError("Kubeconfig must be valid YAML.") from exc
    if not isinstance(data, dict):
        raise ValueError("Kubeconfig must be a YAML mapping.")
    if not isinstance(data.get("contexts"), list) or not data.get("contexts"):
        raise ValueError("Kubeconfig must include a non-empty contexts list.")
    return data


def validate_kubeconfig_connection(raw: str, context_name: str) -> dict[str, Any]:
    """Validate kubeconfig YAML and that the named context exists."""
    data = parse_kubeconfig_yaml(raw)
    ctx = (context_name or "").strip()
    if not ctx:
        raise ValueError("Kubernetes context is required.")
    names: list[str] = []
    for item in data.get("contexts") or []:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if name:
                names.append(name)
    if ctx not in names:
        available = ", ".join(names) if names else "none"
        raise ValueError(f"Context {ctx!r} not found in kubeconfig. Available: {available}")
    return data


def _kubeconfig_cluster_name(data: dict[str, Any], context_name: str) -> str | None:
    ctx_entry = next(
        (
            c
            for c in data.get("contexts") or []
            if isinstance(c, dict) and str(c.get("name") or "").strip() == context_name
        ),
        None,
    )
    if not isinstance(ctx_entry, dict):
        return None
    ctx = ctx_entry.get("context")
    if not isinstance(ctx, dict):
        return None
    cluster_ref = str(ctx.get("cluster") or "").strip()
    if not cluster_ref:
        return None
    cluster_entry = next(
        (
            c
            for c in data.get("clusters") or []
            if isinstance(c, dict) and str(c.get("name") or "").strip() == cluster_ref
        ),
        None,
    )
    if not isinstance(cluster_entry, dict):
        return cluster_ref
    cluster = cluster_entry.get("cluster")
    if isinstance(cluster, dict):
        server = str(cluster.get("server") or "").strip()
        return server or cluster_ref
    return cluster_ref


def _gcp_factory_from_connection(conn: dict[str, Any]):
    from collector.clouds.gcp.client_factory import GcpClientFactory

    auth_method = (conn.get("auth_method") or "").strip().lower()
    project = (conn.get("project") or "").strip() or None
    raw = (conn.get("gcp_service_account_json") or "").strip()
    if auth_method == "adc":
        return GcpClientFactory(project_id=project)
    if raw:
        info = parse_gcp_service_account_json(raw)
        return GcpClientFactory(
            project_id=project or info.get("project_id") or None,
            service_account_info=info,
        )
    return GcpClientFactory(project_id=project)


def _azure_auth_from_connection(conn: dict[str, Any]):
    from collector.lib.models import AzureAuthOptions

    auth_method = (conn.get("auth_method") or "").strip().lower()
    auth = AzureAuthOptions(
        tenant_id=conn.get("azure_tenant_id") or "",
        client_id=conn.get("azure_client_id") or "",
    )
    if auth_method == "certificate":
        auth.client_certificate_content = conn.get("azure_client_certificate_content") or ""
    else:
        auth.client_secret = conn.get("azure_client_secret") or ""
    return auth


def _apply_connection(req: RunLaunchRequest, connection_id: str | None) -> RunLaunchRequest:
    if not connection_id:
        return req
    conn = config_store.get_connection(connection_id)
    platform = (conn.get("platform") or req.cloud or "").strip().lower()
    auth_method = (conn.get("auth_method") or "").strip().lower()

    aws_access_key_id = conn.get("aws_access_key_id") or req.aws_access_key_id
    aws_secret_access_key = conn.get("aws_secret_access_key") or req.aws_secret_access_key
    aws_session_token = conn.get("aws_session_token") or req.aws_session_token
    if platform == "aws" and auth_method == "assume_role":
        creds = _aws_credentials_from_connection(conn)
        if creds:
            aws_access_key_id = creds.get("aws_access_key_id") or aws_access_key_id
            aws_secret_access_key = creds.get("aws_secret_access_key") or aws_secret_access_key
            aws_session_token = creds.get("aws_session_token") or aws_session_token

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
        azure_client_secret=conn.get("azure_client_secret") or req.azure_client_secret,
        azure_client_certificate_content=(
            conn.get("azure_client_certificate_content") or req.azure_client_certificate_content
        ),
        aws_profile=conn.get("profile_name") or req.aws_profile,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        gcp_service_account_json=conn.get("gcp_service_account_json") or req.gcp_service_account_json,
        k8s_context=conn.get("k8s_context") or req.k8s_context,
        kubeconfig_content=conn.get("kubeconfig_content") or req.kubeconfig_content,
        max_records_per_source=req.max_records_per_source,
        artifact_parameters=req.artifact_parameters,
        gcp_log_backend=req.gcp_log_backend,
        pipeline_steps=req.pipeline_steps,
        credentials_path=req.credentials_path,
        out_dir=req.out_dir,
        engagement_id=req.engagement_id,
        key_path=req.key_path,
        reporter=req.reporter,
        artifacts_root=req.artifacts_root,
    )


def _seed_failed_plan(reporter, req, detail: str) -> None:
    """Publish the collector plan as failed when a run died before begin_run ran.

    No-op if the matrix already has rows (the plan was published). Best-effort: if the plan
    itself can't be resolved (e.g. a bad artifact selection was the failure), we leave the
    matrix empty and rely on the error banner.
    """
    if getattr(reporter, "matrix", None) is None or reporter.matrix.rows:
        return
    try:
        from collector.engine.run_launcher import _matrix_meta, _resolve_collectors

        collectors, artifact_refs, collector_cloud = _resolve_collectors(req)
        plan_label, labels, severities = _matrix_meta(
            collector_cloud, artifact_refs, req.artifacts_root or Path("artifacts")
        )
        reporter.begin_run(
            "",
            [],
            req.case_id,
            collectors,
            plan_label=plan_label,
            artifact_labels=labels,
            artifact_severities=severities,
        )
        reporter.matrix.abort_non_terminal(
            detail=detail,
            pending_detail="Run failed before this collector started.",
        )
    except Exception:  # noqa: BLE001 — seeding is best-effort; the error banner still shows
        pass


def _execute_run(run_id: str, body: dict[str, Any]) -> None:
    cloud = body["cloud"]
    case_id = body["case_id"]
    auto_ingest = body.get("auto_ingest", True)
    connection_id = body.get("connection_id")

    run_store.mark_started(run_id)  # real execution start → accurate elapsed/duration
    matrix = MatrixState(severity_resolver=_severity_for_registry(cloud))
    reporter = ApiReporter(
        matrix,
        run_id=run_id,
        sink=run_store,
        cancel_checker=lambda rid=run_id: bool(run_store.get_run(rid).get("cancel_requested")),
    )

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
        azure_client_secret=body.get("azure_client_secret") or "",
        azure_client_certificate_content=body.get("azure_client_certificate_content") or "",
        aws_profile=body.get("aws_profile") or "",
        max_records_per_source=body.get("max_records_per_source"),
        artifact_parameters=body.get("artifact_parameters") or {},
        gcp_log_backend=body.get("gcp_log_backend"),
        artifacts_root=settings.artifacts_root,
        reporter=reporter,
        pipeline_steps=["package"] + (["ingest"] if auto_ingest else []),
    )
    try:
        req = _apply_connection(req, connection_id)
    except ConfigNotFound as exc:
        run_store.finalize(run_id, status="failed", error=str(exc))
        return

    try:
        package = launch_collection(req)
    except Exception as exc:  # noqa: BLE001
        # A run can fail during preflight (identity/DNS/auth) BEFORE the runner publishes its
        # collector plan via begin_run — leaving the matrix empty and the UI spinning on
        # "Waiting for collector…". Seed the plan and mark it failed so the operator sees the
        # collectors (as failed) plus the error instead of a perpetual spinner.
        _seed_failed_plan(reporter, req, str(exc))
        reporter.finalize()
        run_store.finalize(run_id, status="failed", error=str(exc))
        run_store.append_event(run_id, {"type": "error", "message": str(exc)})
        return

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
    if auto_ingest and not run_store.get_run(run_id).get("cancel_requested"):
        from collector.engine.run_finalize import PIPELINE_INGEST, ingest_progress_reporter

        reporter.start_step(PIPELINE_INGEST, "Opening evidence package…")
        try:
            from ventra_ingester.pipeline import ingest_package

            result = ingest_package(
                package.path,
                settings.case_store,
                reporter=ingest_progress_reporter(reporter),
            )
            ingest_result = {
                "case_id": result.case_id,
                "events": result.event_count,
                "integrity": result.integrity_overall,
                "warnings": result.warnings,
            }
            extra["ingest"] = ingest_result
            reporter.finish_step(
                PIPELINE_INGEST,
                success=True,
                detail=f"{result.event_count:,} events loaded · integrity {result.integrity_overall}",
                records=result.event_count,
            )
            run_store.append_event(run_id, {"type": "ingested", **ingest_result})
        except Exception as exc:  # noqa: BLE001
            reporter.finish_step(
                PIPELINE_INGEST,
                success=False,
                detail=str(exc),
            )
            extra["ingest_error"] = str(exc)
            run_store.append_event(run_id, {"type": "ingest_error", "message": str(exc)})

    reporter.finalize()

    cancelled = bool(run_store.get_run(run_id).get("cancel_requested"))
    if cancelled:
        # Reporter drains its in-memory matrix (aborting anything still non-terminal), then
        # we stamp the on-disk matrix terminal so meta + matrix + rows all agree.
        reporter.abort_remaining()
        try:
            matrix_snap = run_store.get_matrix(run_id)
            run_store._apply_cancel_to_matrix(matrix_snap, status="cancelled")
            run_store.update_matrix(run_id, matrix_snap)
        except RunNotFound:
            pass
        extra.pop("ingest", None)
    final_status = "cancelled" if cancelled else "completed"
    run_store.finalize(run_id, status=final_status, extra=extra)
    run_store.append_event(run_id, {"type": final_status})


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
        except Exception as exc:  # noqa: BLE001 — a crashing worker must not vanish silently
            try:
                run_store.finalize(run_id, status="failed", error=f"Run crashed: {exc}")
                run_store.append_event(run_id, {"type": "error", "message": str(exc)})
            except Exception:  # noqa: BLE001
                pass
        finally:
            # Safety net: whatever happened, a run must land on a terminal status so the UI
            # never gets stuck showing "running" or "cancelling" for a dead worker.
            try:
                meta = run_store.get_run(run_id)
                if str(meta.get("status") or "") not in _TERMINAL_STATUSES:
                    if meta.get("cancel_requested"):
                        _finalize_cancelled(run_id)
                    else:
                        run_store.finalize(
                            run_id, status="failed", error="Run ended without finalizing."
                        )
                        run_store.append_event(run_id, {"type": "failed"})
            except Exception:  # noqa: BLE001
                pass
            with _active_lock:
                _active_runs.discard(run_id)

    thread = threading.Thread(target=_runner, name=f"ventra-run-{run_id}", daemon=True)
    thread.start()
    return record


def is_run_active(run_id: str) -> bool:
    """True while a worker thread is executing this run."""
    with _active_lock:
        return run_id in _active_runs


def _finalize_cancelled(run_id: str) -> dict[str, Any]:
    """Stamp a run terminal as cancelled: repaint matrix, append event, finalize meta."""
    try:
        matrix = run_store.get_matrix(run_id)
        run_store._apply_cancel_to_matrix(matrix, status="cancelled")
        run_store.update_matrix(run_id, matrix)
    except RunNotFound:
        pass
    run_store.append_event(run_id, {"type": "cancelled", "message": "Cancelled by operator"})
    return run_store.finalize(run_id, status="cancelled")


def reclaim_orphaned_runs(*, run_id: str | None = None) -> None:
    """Finalize cancelled/cancelling runs whose worker is gone so they never stick forever.

    After a process restart ``_active_runs`` is empty, so a run left in ``cancelling`` would
    otherwise sit there indefinitely. Call this from list/get so the UI self-heals.
    """
    try:
        metas = [run_store.get_run(run_id)] if run_id else run_store.list_runs()
    except RunNotFound:
        return
    for meta in metas:
        rid = str(meta.get("run_id") or "")
        status = str(meta.get("status") or "")
        if not rid or status in _TERMINAL_STATUSES or is_run_active(rid):
            continue
        if status == "cancelling" or meta.get("cancel_requested"):
            try:
                _finalize_cancelled(rid)
            except Exception:  # noqa: BLE001 — best-effort heal; never break list/get
                pass


def cancel_run(run_id: str) -> dict[str, Any]:
    """Request cancellation and finalize to ``cancelled`` immediately.

    Flags ``cancel_requested`` so any live worker stops collectors, then stamps meta + matrix
    terminal right away so the UI never sits on ``cancelling`` waiting for a worker that may
    already be dead (or hang for days). Idempotent on terminal runs.
    """
    meta = run_store.get_run(run_id)
    if str(meta.get("status") or "") in _TERMINAL_STATUSES:
        return meta
    run_store.request_cancel(run_id)
    return _finalize_cancelled(run_id)


async def start_run_async(body: dict[str, Any]) -> dict[str, Any]:
    """Async wrapper that offloads thread startup."""
    return await asyncio.to_thread(start_run, body)


def test_connection(connection_id: str) -> dict[str, Any]:
    """Best-effort identity check for a saved connection."""
    conn = config_store.get_connection(connection_id)
    platform = (conn.get("platform") or "").strip().lower()
    try:
        if platform == "aws":
            session = _aws_session_from_connection(conn)
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

            auth = _azure_auth_from_connection(conn)
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
            factory = _gcp_factory_from_connection(conn)
            ident = factory.caller_identity()
            return {
                "ok": True,
                "platform": platform,
                "project_id": ident.project_id,
                "principal": ident.principal,
            }
        if platform == "kubernetes":
            context = (conn.get("k8s_context") or "").strip()
            raw = (conn.get("kubeconfig_content") or "").strip()
            data = validate_kubeconfig_connection(raw, context)
            cluster = _kubeconfig_cluster_name(data, context)
            return {
                "ok": True,
                "platform": platform,
                "context": context,
                "cluster": cluster,
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

