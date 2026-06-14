# Ventra Console

The analyst investigation GUI. Two parts:

- **`backend/`** — FastAPI, a thin read-only query layer over the case store (DuckDB over
  Parquet + JSON sidecars). RBAC enforced server-side. No outbound calls.
- **`frontend/`** — Next.js + Tailwind. One module per panel. URL-addressable state, keyboard
  navigation, dark/light/high-contrast themes. No telemetry, all assets local.

## Run it

From a clone, one command starts both halves with hot reload (no Docker):

```bash
ventra gui        # http://localhost:8080  (first run sets up .venv + npm)
```

A packaged desktop app is planned for the v1 release. To run the pieces by hand during
development:

```bash
# Backend (serves the case store the ingester writes to)
pip install ./backend
VENTRA_CASE_STORE=../cases ventra-console      # http://127.0.0.1:8000

# Frontend
cd frontend && npm install && npm run dev      # http://localhost:8080  (proxies /api → backend)
```

## Panels

| Panel | Purpose |
|-------|---------|
| Overview | Account context, collection completeness (gaps as evidence), quick stats, distributions |
| Timeline | Every source on one brushable time axis; filter rail; event table |
| CloudTrail Analyzer | Control-plane deep dive with saved views and user-agent breakdown |
| Identity | IAM principals, key hygiene, and the role-assumption graph |
| Network | VPC flow top talkers (public-egress = exfil lens) and rejected flows |
| Resources | EC2 / S3 inventory with exposure + shared-snapshot highlighting |
| Findings | Merged GuardDuty / Security Hub / Inspector / Macie, with pivots |
| Search | Full-text + structured query across the case |
| IOCs & Hunts | ATT&CK Cloud coverage map and curated hunt packs |
| Report | Pin evidence, write the narrative, export Markdown |
| Settings | Theme/density, RBAC roles, backend status, privacy |

## Cross-cutting

- **Pivot everywhere** — every IP / principal / ARN opens a menu to jump to that entity in
  any panel with the filter pre-applied.
- **URL state** — filters, time windows, and selections live in the URL; share a link to a
  view.
- **Keyboard** — `⌘K` palette, `/` search, `g t/c/i/n/r/f` to jump between panels.
