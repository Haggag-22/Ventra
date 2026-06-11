# Harbor Console Backend

FastAPI service that exposes the case store to the frontend. It is intentionally thin: all
investigative logic is data in the case store, and all queries flow through one safe,
parameterized path (`app/store.py`). RBAC is enforced here, server-side.

## Endpoints (by panel)

| Method | Path | Panel |
|--------|------|-------|
| GET | `/api/cases` | Cases list |
| GET | `/api/cases/{id}/summary` | Overview |
| GET | `/api/cases/{id}/integrity` | Integrity badge / report |
| GET | `/api/cases/{id}/events` | Timeline / CloudTrail / Search (filter, sort, paginate, pivot) |
| GET | `/api/cases/{id}/events/facets` | Filter rail aggregations |
| GET | `/api/cases/{id}/timeline` | Brushable timeline points |
| GET | `/api/cases/{id}/findings` | Findings |
| GET | `/api/cases/{id}/identity` | IAM inventory + role-assumption graph |
| GET | `/api/cases/{id}/network` | VPC flow top talkers / rejected |
| GET | `/api/cases/{id}/resources` | EC2 / S3 inventory |
| GET | `/api/cases/{id}/inventory/{source}` | Raw inventory snapshot |
| POST | `/api/cases/import` | Ingest an uploaded package (RBAC: `import_case`) |

## Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `HARBOR_CASE_STORE` | `./cases` | Root the ingester writes to. |
| `HARBOR_UPLOAD_DIR` | `./.harbor-uploads` | Staging for uploaded packages. |
| `HARBOR_CORS` | `localhost:3000,8080` | Allowed frontend origins. |

Telemetry is off and not configurable. The service makes no outbound calls.

## Run

```bash
pip install .
HARBOR_CASE_STORE=../../cases harbor-console     # uvicorn on 127.0.0.1:8000
```

## Auth / RBAC

Roles (`responder`, `investigator`, `data_custodian`, `analyst`) gate capabilities. For local
single-analyst use the default is `investigator`. A deployment can front the API with OIDC and
pass the role via the `X-Harbor-Role` header.
