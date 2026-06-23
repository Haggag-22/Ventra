"""Ventra console backend — FastAPI app exposing the case store to the frontend.

Endpoints are grouped by panel. Everything is read-only over the case store except the import
endpoint, which runs the ingester. No outbound calls, no telemetry.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from . import __version__
from .config import settings
from .rbac import Role, _check, current_role
from .store import CaseNotFound, EventQuery, store


class AcquisitionBuildRequest(BaseModel):
    """Body for POST /api/acquisitions/build — select a cloud + artifacts (or a pack)."""

    cloud: str
    case_id: str = "CASE-PENDING"
    artifacts: list[str] = []
    pack: str | None = None
    include_iam: bool = True
    since: str = ""
    until: str = ""
    regions: list[str] = []
    project: str = ""
    subscription: str = ""
    max_records_per_source: int | None = None
    artifact_parameters: dict[str, dict[str, Any]] = {}
    deployment_profile: str = "cloudshell"
    transport: str = ""


class AcquisitionPreviewRequest(AcquisitionBuildRequest):
    """Same shape as build — used for IAM / metadata preview only."""


class S3ImportRequest(BaseModel):
    s3_prefix: str = ""


_ALLOWED_PROFILES = frozenset({"cloudshell", "workstation", "ec2", "enterprise"})


app = FastAPI(
    title="Ventra Console API",
    version=__version__,
    description="Read-only analyst console over Ventra evidence packages. No telemetry.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.exception_handler(CaseNotFound)
async def _case_not_found(_, exc: CaseNotFound) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": f"Case not found: {exc}"})


# -- meta --------------------------------------------------------------------------------

@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "telemetry": settings.telemetry,
            "case_store": str(settings.case_store)}


@app.get("/api/me")
def me(role: Role = Depends(current_role)) -> dict[str, Any]:
    from .rbac import CAPABILITIES

    return {
        "role": role.value,
        "capabilities": sorted(cap for cap, roles in CAPABILITIES.items() if role in roles),
    }


# -- cases -------------------------------------------------------------------------------

@app.get("/api/cases")
def list_cases(_: Role = Depends(_check("view_case"))) -> dict[str, Any]:
    return {"cases": store.list_cases()}


@app.get("/api/cases/{case_id}/summary")
def case_summary(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.summary(case_id)


@app.get("/api/cases/{case_id}/integrity")
def case_integrity(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.integrity(case_id)


@app.get("/api/cases/{case_id}/manifest")
def case_manifest(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.manifest(case_id)


@app.get("/api/cases/{case_id}/collection-log")
def case_collection_log(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return {"entries": store.collection_log(case_id)}


# -- events (CloudTrail / Search / Pivot all flow through here) -------------------------

def _event_query(
    q: str | None = Query(None, description="Free-text search."),
    source: list[str] | None = Query(None),
    severity: list[str] | None = Query(None),
    category: list[str] | None = Query(None),
    trail_category: list[str] | None = Query(None),
    finding_class: list[str] | None = Query(None),
    actions: list[str] | None = Query(None),
    regions: list[str] | None = Query(None),
    services: list[str] | None = Query(None),
    users: list[str] | None = Query(None),
    action: str | None = Query(None),
    user: str | None = Query(None),
    user_type: str | None = Query(None),
    ip: str | None = Query(None),
    outcome: str | None = Query(None),
    region: str | None = Query(None),
    service: str | None = Query(None),
    kind: str | None = Query(None),
    ua_category: str | None = Query(None),
    related_ip: str | None = Query(None),
    related_user: str | None = Query(None),
    related_resource: str | None = Query(None),
    resources: list[str] | None = Query(None),
    http_status: list[str] | None = Query(None),
    outcomes: list[str] | None = Query(None),
    source_ips: list[str] | None = Query(None),
    dest_ips: list[str] | None = Query(None),
    dest_ports: list[str] | None = Query(None),
    vpc: list[str] | None = Query(None),
    data_access: bool = Query(False),
    since: str | None = Query(None),
    until: str | None = Query(None),
    sort: str = Query("timestamp"),
    order: str = Query("asc"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
) -> EventQuery:
    filters: dict[str, str] = {}
    if action:
        filters["event_action"] = action
    if user:
        filters["user_name"] = user
    if user_type:
        filters["user_type"] = user_type
    if ip:
        filters["source_ip"] = ip
    if outcome:
        filters["event_outcome"] = outcome
    if region:
        filters["cloud_region"] = region
    if service:
        filters["cloud_service"] = service
    if kind:
        filters["event_kind"] = kind
    if ua_category:
        filters["ua_category"] = ua_category
    return EventQuery(
        filters=filters,
        q=q,
        since=since,
        until=until,
        severities=severity or [],
        sources=source or [],
        categories=category or [],
        trail_categories=trail_category or [],
        finding_classes=finding_class or [],
        actions=actions or [],
        regions=regions or [],
        services=services or [],
        users=users or [],
        related_ip=related_ip,
        related_user=related_user,
        related_resource=related_resource,
        resources=resources or [],
        http_status=http_status or [],
        outcomes=outcomes or [],
        source_ips=source_ips or [],
        dest_ips=dest_ips or [],
        dest_ports=dest_ports or [],
        vpcs=vpc or [],
        data_access=data_access,
        sort=sort,
        order=order,
        limit=limit,
        offset=offset,
    )


@app.get("/api/cases/{case_id}/events")
def events(case_id: str, q: EventQuery = Depends(_event_query),
           _: Role = Depends(_check("view_case"))) -> dict:
    return store.query_events(case_id, q)


@app.get("/api/cases/{case_id}/events/facets")
def event_facets(case_id: str, q: EventQuery = Depends(_event_query),
                 _: Role = Depends(_check("view_case"))) -> dict:
    return store.facets(case_id, q)


@app.get("/api/cases/{case_id}/cloudtrail/collection")
def cloudtrail_collection(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.cloudtrail_collection(case_id)


# -- findings ----------------------------------------------------------------------------

@app.get("/api/cases/{case_id}/findings")
def findings(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    q = EventQuery(filters={"event_kind": "finding"}, sort="event_severity", order="desc",
                   limit=500)
    return store.query_events(case_id, q)


# -- identity ----------------------------------------------------------------------------

@app.get("/api/cases/{case_id}/identity")
def identity(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    iam = store.inventory(case_id, "iam") or store.inventory(case_id, "rbac")
    return {
        "iam": iam,
        "graph": store.role_assumption_graph(case_id),
    }


# -- network -----------------------------------------------------------------------------

@app.get("/api/cases/{case_id}/network/vpcs")
def network_vpcs(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.network_vpcs(case_id)


@app.get("/api/cases/{case_id}/network")
def network(
    case_id: str,
    vpc: str | None = Query(None, description="Filter stats to one VPC / network scope."),
    _: Role = Depends(_check("view_case")),
) -> dict:
    return store.network_overview(case_id, vpc_id=vpc or None)


@app.get("/api/cases/{case_id}/web-dns")
def web_dns(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.web_dns_overview(case_id)


@app.get("/api/cases/{case_id}/data-access")
def data_access(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.data_access_overview(case_id)


# -- resources / inventory ---------------------------------------------------------------

@app.get("/api/cases/{case_id}/resources")
def resources(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.inventory_summary(case_id)


@app.get("/api/cases/{case_id}/inventory/summary")
def inventory_summary(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.inventory_summary(case_id)


@app.get("/api/cases/{case_id}/inventory/{source}")
def inventory(case_id: str, source: str, _: Role = Depends(_check("view_case"))) -> dict:
    data = store.inventory(case_id, source)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No inventory for source '{source}'.")
    return {"source": source, "data": data}


# -- evidence file browser (raw collected sources) ---------------------------------------

@app.get("/api/cases/{case_id}/evidence")
def evidence_index(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    from .evidence import EvidenceNotFound, list_evidence_files

    try:
        manifest = store.manifest(case_id)
        return list_evidence_files(store.case_dir(case_id), manifest)
    except CaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EvidenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/cases/{case_id}/evidence/content")
def evidence_content(
    case_id: str,
    path: str = Query(..., min_length=1),
    max_bytes: int | None = Query(None, ge=1),
    _: Role = Depends(_check("view_case")),
) -> dict:
    from .evidence import EvidenceError, EvidenceNotFound, read_evidence_text

    try:
        store.case_dir(case_id)
        return read_evidence_text(store.case_dir(case_id), path, max_bytes=max_bytes)
    except CaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EvidenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EvidenceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/cases/{case_id}/evidence/lines")
def evidence_lines(
    case_id: str,
    path: str = Query(..., min_length=1),
    offset: int = Query(0, ge=0),
    limit: int | None = Query(None, ge=1),
    _: Role = Depends(_check("view_case")),
) -> dict:
    from .evidence import EvidenceError, EvidenceNotFound, read_evidence_lines

    try:
        store.case_dir(case_id)
        return read_evidence_lines(store.case_dir(case_id), path, offset=offset, limit=limit)
    except CaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EvidenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EvidenceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/cases/{case_id}/evidence/download")
def evidence_download(
    case_id: str,
    path: str = Query(..., min_length=1),
    _: Role = Depends(_check("view_case")),
) -> FileResponse:
    from .evidence import EvidenceError, EvidenceNotFound, read_evidence_bytes

    try:
        store.case_dir(case_id)
        target, media = read_evidence_bytes(store.case_dir(case_id), path)
    except CaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EvidenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EvidenceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return FileResponse(
        target,
        media_type=media,
        filename=target.name,
        headers={"Content-Disposition": f'attachment; filename="{target.name}"'},
    )


# -- acquire (artifact library + kit builder) --------------------------------------------

def _artifact_view(art: dict[str, Any], *, full: bool = False) -> dict[str, Any]:
    view = {
        "name": art.get("name", ""),
        "collector": art.get("collector", ""),
        "cloud": art.get("cloud", ""),
        "category": art.get("category", ""),
        "description": art.get("description", ""),
        "version": art.get("version", ""),
        "severity": art.get("severity", ""),
        "estimated_volume": art.get("estimated_volume", ""),
        "required_actions": art.get("required_actions", []),
        "parameters": art.get("parameters", {}),
        "implicit": bool(art.get("implicit")),
        "selectable": art.get("selectable", True) is not False and not art.get("implicit"),
    }
    if full:
        view["aliases"] = art.get("aliases", [])
        view["sources"] = art.get("sources", [])
    return view


@app.get("/api/artifacts")
def list_artifacts(
    cloud: str | None = Query(None),
    search: str | None = Query(None),
    _: Role = Depends(current_role),
) -> dict:
    from collector.engine.loader import load_artifacts_dir

    arts = [_artifact_view(a) for a in load_artifacts_dir(settings.artifacts_root, cloud=cloud)]
    arts = [a for a in arts if a.get("selectable", True)]
    if search:
        s = search.lower()
        arts = [
            a for a in arts
            if s in a["name"].lower()
            or s in a["collector"].lower()
            or s in a["description"].lower()
            or s in a["category"].lower()
        ]
    return {"artifacts": arts, "count": len(arts)}


@app.get("/api/artifacts/{collector}")
def get_artifact(
    collector: str, cloud: str | None = Query(None), _: Role = Depends(current_role)
) -> dict:
    from collector.engine.loader import load_artifacts_dir

    for a in load_artifacts_dir(settings.artifacts_root, cloud=cloud):
        if collector in (a.get("collector"), a.get("name"), *(a.get("aliases") or [])):
            return _artifact_view(a, full=True)
    raise HTTPException(status_code=404, detail=f"No artifact for collector '{collector}'.")


@app.get("/api/packs")
def list_acquisition_packs(cloud: str | None = Query(None), _: Role = Depends(current_role)) -> dict:
    from collector.engine.acquisition import list_packs

    return {"packs": list_packs(cloud, settings.artifacts_root)}


def _resolve_acquisition_request(body: AcquisitionBuildRequest) -> tuple[str, list[str], list[Path] | None]:
    """Validate cloud + artifact selection; return (cloud, collector names, optional IAM paths)."""
    from collector.engine.acquisition import AcquisitionError, augment_collectors, load_pack

    cloud = body.cloud.strip().lower()
    if cloud not in ("aws", "azure", "gcp"):
        raise HTTPException(status_code=400, detail=f"Unsupported cloud: {body.cloud!r}")

    names = list(body.artifacts or [])
    if body.pack:
        try:
            names = load_pack(body.pack, settings.artifacts_root)
        except AcquisitionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not names:
        raise HTTPException(status_code=400, detail="Select at least one artifact or a pack.")

    names = augment_collectors(cloud, names)
    iam_paths: list[Path] | None = None
    if body.include_iam:
        iam = settings.artifacts_root.parent / "docs" / "iam-policies" / f"{cloud}-collector-readonly.json"
        if iam.is_file():
            iam_paths = [iam]
    return cloud, names, iam_paths


@app.post("/api/acquisitions/preview")
def preview_acquisition(
    body: AcquisitionPreviewRequest, _: Role = Depends(_check("build_acquisition"))
) -> dict[str, Any]:
    from collector.kit.preview import preview_kit

    cloud, names, iam_paths = _resolve_acquisition_request(body)
    profile = body.deployment_profile.strip().lower() or "cloudshell"
    if profile not in _ALLOWED_PROFILES:
        raise HTTPException(status_code=400, detail=f"Unknown deployment profile: {body.deployment_profile!r}")
    try:
        preview = preview_kit(
            cloud=cloud,
            artifact_names=names,
            artifacts_root=settings.artifacts_root,
            iam_policy_paths=iam_paths,
            include_iam=body.include_iam,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    preview["deployment_profile"] = profile
    preview["bundle_wheel"] = True
    from collector.kit.build import kit_wheel_source

    preview["wheel_source"] = kit_wheel_source()
    return preview


@app.post("/api/acquisitions/build")
def build_acquisition(
    body: AcquisitionBuildRequest, _: Role = Depends(_check("build_acquisition"))
) -> Response:
    import tempfile

    from collector.kit.build import build_kit

    cloud, names, iam_paths = _resolve_acquisition_request(body)
    case_id = _normalize_case_id(body.case_id) or "CASE-PENDING"
    profile = body.deployment_profile.strip().lower() or "cloudshell"
    if profile not in _ALLOWED_PROFILES:
        raise HTTPException(status_code=400, detail=f"Unknown deployment profile: {body.deployment_profile!r}")

    with tempfile.TemporaryDirectory(prefix="ventra-kit-") as tmp:
        out = Path(tmp) / "kit.zip"
        try:
            build_kit(
                out,
                cloud=cloud,
                case_id=case_id,
                artifact_names=names,
                artifacts_root=settings.artifacts_root,
                iam_policy_paths=iam_paths,
                since=body.since.strip(),
                until=body.until.strip(),
                regions=[r.strip() for r in body.regions if r.strip()] or None,
                project=body.project.strip(),
                subscription=body.subscription.strip(),
                max_records_per_source=body.max_records_per_source,
                artifact_parameters=body.artifact_parameters or None,
                transport=body.transport.strip(),
                bundle_wheel=True,
                require_wheel=True,
                deployment_profile=profile,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        data = out.read_bytes()

    filename = f"ventra-kit-{cloud}-{case_id}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# -- import (RBAC: import_case) ----------------------------------------------------------

@app.post("/api/cases/import")
async def import_case(
    file: UploadFile,
    case_id: str | None = Form(None),
    _: Role = Depends(_check("import_case")),
) -> dict:
    import shutil

    from ventra_ingester.pipeline import ingest_package

    override = _normalize_case_id(case_id)
    dest = settings.upload_dir / _safe_upload_name(file.filename)
    await _stream_upload(file, dest)
    try:
        result = ingest_package(dest, settings.case_store, case_id_override=override)
        package_dir = result.case_dir / "package"
        package_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dest, package_dir / dest.name)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Ingest failed: {exc}") from exc
    return {
        "case_id": result.case_id,
        "events": result.event_count,
        "integrity": result.integrity_overall,
        "sources_loaded": result.sources_loaded,
        "inventory_loaded": result.inventory_loaded,
        "warnings": result.warnings,
    }


@app.get("/api/enterprise/settings")
def enterprise_settings(_: Role = Depends(_check("import_case"))) -> dict[str, Any]:
    return {
        "ingest_s3_prefix": settings.ingest_s3_prefix,
        "max_upload_mb": settings.max_upload_mb,
    }


@app.post("/api/cases/import/s3")
def import_cases_from_s3(
    body: S3ImportRequest,
    _: Role = Depends(_check("import_case")),
) -> dict[str, Any]:
    from ventra_ingester.ingest_watch import poll_s3_once

    prefix = (body.s3_prefix or settings.ingest_s3_prefix).strip()
    if not prefix:
        raise HTTPException(
            status_code=400,
            detail="Set VENTRA_INGEST_S3_PREFIX on the backend or provide s3_prefix in the request.",
        )
    try:
        result = poll_s3_once(
            prefix,
            settings.case_store,
            download_dir=settings.ingest_download_dir,
            state_file=settings.ingest_state_file,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ingested": [
            {
                "case_id": item.case_id,
                "events": item.event_count,
                "integrity": item.integrity,
                "s3_key": item.s3_key,
                "warnings": item.warnings,
            }
            for item in result.ingested
        ],
        "skipped": result.skipped,
        "errors": result.errors,
    }


@app.post("/api/cases/{case_id}/export/elastic")
def export_case_elastic(
    case_id: str,
    background_tasks: BackgroundTasks,
    _: Role = Depends(_check("export_report")),
) -> FileResponse:
    """Export ingested case events as an NDJSON zip for Logstash pickup."""
    import shutil
    import tempfile
    import zipfile

    from ventra_ingester.exporters.elastic_ndjson import export_elastic_ndjson

    case_dir = store.case_dir(case_id)
    tmp = Path(tempfile.mkdtemp(prefix="ventra-export-"))
    try:
        out_dir = tmp / "export"
        export_elastic_ndjson(case_dir, out_dir)
        zip_path = tmp / f"{case_id}-elastic-export.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(out_dir.rglob("*")):
                if path.is_file():
                    zf.write(path, arcname=path.relative_to(out_dir).as_posix())
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(tmp, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Export failed: {exc}") from exc
    background_tasks.add_task(shutil.rmtree, tmp, True)
    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"{case_id}-elastic-export.zip",
    )


# -- delete (RBAC: delete_case — Data Custodian only) ------------------------------------

@app.delete("/api/cases/{case_id}")
def delete_case(case_id: str, _: Role = Depends(_check("delete_case"))) -> dict:
    store.case_dir(case_id)  # raises CaseNotFound -> 404 if absent
    store.delete_case(case_id)
    return {"deleted": case_id}


def _safe_upload_name(filename: str | None) -> str:
    """Reduce a client-supplied filename to a safe basename inside the upload dir.

    Strips any directory components (defeats ``../`` path traversal) and keeps only a
    conservative character set, so a malicious ``filename`` can never write outside
    ``settings.upload_dir``.
    """
    from pathlib import PurePosixPath, PureWindowsPath

    raw = (filename or "").strip()
    # Take the last path component under either separator convention.
    base = PureWindowsPath(PurePosixPath(raw).name).name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    return base or "package.tar.zst"


async def _stream_upload(file: UploadFile, dest: Path) -> None:
    """Stream an upload to ``dest`` in chunks, rejecting anything over the size cap.

    Reading the whole body into memory (``await file.read()``) lets a single request
    exhaust RAM; streaming with a running total bounds both memory and disk use.
    """
    limit = settings.max_upload_mb * 1024 * 1024
    written = 0
    try:
        with dest.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > limit:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Package exceeds the {settings.max_upload_mb} MB upload limit.",
                    )
                out.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise


def _normalize_case_id(raw: str | None) -> str | None:
    if raw is None:
        return None
    cid = raw.strip()
    if not cid:
        return None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", cid):
        raise HTTPException(status_code=400, detail="Invalid case ID.")
    return cid


def run() -> None:  # console-script entry point
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":  # pragma: no cover
    run()
