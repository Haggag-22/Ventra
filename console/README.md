# Ventra Console

The analyst investigation GUI. Two parts:

- **`backend/`** — FastAPI, a thin read-only query layer over the case store (DuckDB over
  Parquet + JSON sidecars). RBAC enforced server-side. No outbound calls.
- **`frontend/`** — Next.js + Tailwind. One module per panel. URL-addressable state, keyboard
  navigation, dark/light/high-contrast themes. No telemetry, all assets local.

## Run it

**Installed from PyPI** (`uv tool install ventra` / `pipx install ventra`): the console is
bundled in the package. Run `ventra gui` and open `http://127.0.0.1:8000` — one process serves
both the API and the UI. No Node.js, npm or clone needed; everything below is for developers.

**From a source checkout**, `ventra gui` (alias `ventra dev`) starts both halves with hot
reload (no Docker; the first run sets up `.venv` and runs `npm install`):

```bash
ventra gui        # console at http://localhost:8080, API at :8000
```

This starts the FastAPI backend (default `:8000`, `--backend-port`) and the Next.js dev server
(default `:8080`, `--port`). The frontend proxies `/api/*` to the backend via `VENTRA_API`.
Pass `--dev-source` to force this mode when a bundled build is also present.

**Do not run `npm run dev` alone on `:3000` without the backend** — pages like Acquire
call `/api/artifacts` and will hang or fail if nothing is listening on `:8000`. If you see
"Can't reach backend", stop stray dev servers and run `ventra gui` from the repo root:

```bash
lsof -ti :8000,:8080,:3000 | xargs kill -9   # free stuck ports (optional)
ventra gui
```

To run the pieces by hand during development:

```bash
# Backend (serves the case store the ingester writes to)
pip install ./backend
VENTRA_CASE_STORE=../cases ventra-console      # http://127.0.0.1:8000

# Frontend
cd frontend && npm install && VENTRA_API=http://127.0.0.1:8000 npm run dev   # :3000, proxies /api → backend
```

## Panels

Titles follow the case cloud (AWS defaults below; Azure and GCP rename several panels via
`panel-labels.ts`). Collector chips in each panel header come from `panel-collectors.ts`.

### Investigate

| Panel | Purpose |
|-------|---------|
| CloudTrail Timeline | Control-plane event table (CloudTrail / Activity Log / Entra / Cloud Audit). Filter by source, action, principal, IP, region, trail category. |
| CloudWatch Logs | CloudWatch log group events (shown for AWS cases only). |
| Security Findings | Merged detections: GuardDuty / Security Hub / Inspector / Macie / Detective / Config; Defender; SCC / Cloud Monitoring. |
| Identity & Access | IAM / Entra / RBAC principals and policies; KMS and Secrets inventory when collected. |
| Network Activity | VPC / VNet / NSG / firewall flow volume, public egress, rejected flows. |
| Web & DNS | Edge access logs, WAF sampled requests, DNS resolver / Cloud DNS queries. |
| Kubernetes Audit | EKS / AKS / GKE API-server audit logs. |
| Data Access | Object-level and secret access (S3, storage, Key Vault, GCS, BigQuery, Cloud SQL, Secret Manager). |
| Logs Coverage | Per-collector collected / partial / empty / denied / not-run status from the manifest, including gaps. |

### Package

| Panel | Purpose |
|-------|---------|
| Resource Inventory | EC2 / S3 / Lambda / ARM / GCE and related inventory snapshots. |
| Raw Evidence | Browse and download sealed source files from the package. |

## Cross-cutting

- **Pivot everywhere** — every IP / principal / ARN opens a menu to jump to that entity in
  any panel with the filter pre-applied.
- **URL state** — filters, time windows, and selections live in the URL; share a link to a
  view.
- **Keyboard** — `⌘K` / `Ctrl+K` palette, `/` open palette, `g` then `t`/`c` timeline,
  `f` findings, `i` identity, `n` network, `a` logs coverage.
