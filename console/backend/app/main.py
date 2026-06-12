"""Ventra console backend — FastAPI app exposing the case store to the frontend.

Endpoints are grouped by panel. Everything is read-only over the case store except the import
endpoint, which runs the ingester. No outbound calls, no telemetry.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .config import settings
from .rbac import Role, _check, current_role
from .store import CaseNotFound, EventQuery, store

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
    return {"role": role.value}


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


# -- events (Timeline / CloudTrail / Search / Pivot all flow through here) ----------------

def _event_query(
    q: str | None = Query(None, description="Free-text search."),
    source: list[str] | None = Query(None),
    severity: list[str] | None = Query(None),
    category: list[str] | None = Query(None),
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
        actions=actions or [],
        regions=regions or [],
        services=services or [],
        users=users or [],
        related_ip=related_ip,
        related_user=related_user,
        related_resource=related_resource,
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


@app.get("/api/cases/{case_id}/timeline")
def timeline(case_id: str, q: EventQuery = Depends(_event_query),
             _: Role = Depends(_check("view_case"))) -> dict:
    return store.timeline_buckets(case_id, q)


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
    return {
        "iam": store.inventory(case_id, "iam"),
        "graph": store.role_assumption_graph(case_id),
    }


# -- network -----------------------------------------------------------------------------

@app.get("/api/cases/{case_id}/network")
def network(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    return store.network_overview(case_id)


# -- resources / inventory ---------------------------------------------------------------

@app.get("/api/cases/{case_id}/resources")
def resources(case_id: str, _: Role = Depends(_check("view_case"))) -> dict:
    sources = store.inventory_sources(case_id)
    return {
        "sources": sources,
        "ec2": store.inventory(case_id, "ec2"),
        "s3": store.inventory(case_id, "s3"),
        "account": store.inventory(case_id, "account"),
    }


@app.get("/api/cases/{case_id}/inventory/{source}")
def inventory(case_id: str, source: str, _: Role = Depends(_check("view_case"))) -> dict:
    data = store.inventory(case_id, source)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No inventory for source '{source}'.")
    return {"source": source, "data": data}


# -- import (RBAC: import_case) ----------------------------------------------------------

@app.post("/api/cases/import")
async def import_case(
    file: UploadFile,
    case_id: str | None = Form(None),
    _: Role = Depends(_check("import_case")),
) -> dict:
    from ventra_ingester.pipeline import ingest_package

    override = _normalize_case_id(case_id)
    dest = settings.upload_dir / (file.filename or "package.tar.zst")
    dest.write_bytes(await file.read())
    try:
        result = ingest_package(dest, settings.case_store, case_id_override=override)
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
