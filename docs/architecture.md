# Harbor architecture

Three loosely-coupled tiers, one contract.

```
┌──────────────────────────┐     evidence        ┌──────────────────────────┐
│  COLLECTOR               │     package         │  INGESTER                │
│  client cloud shell      │  ───────────────►   │  IR workstation          │
│  read-only IAM           │  sealed .tar.zst    │  verify → parse →        │
│  AWS first               │  + signed manifest  │  normalize → load        │
└──────────────────────────┘                     └────────────┬─────────────┘
                                                              │ DuckDB / Parquet
                                                              ▼
                                                 ┌──────────────────────────┐
                                                 │  CONSOLE                 │
                                                 │  FastAPI + Next.js       │
                                                 │  case-scoped, RBAC,      │
                                                 │  offline, no telemetry   │
                                                 └──────────────────────────┘
```

## The contract

The only thing that crosses tier boundaries is the **Evidence Package Format**
([spec](evidence-package-format.md)). Because it's the single contract:

- The collector can add sources without the console changing — the ingester maps new sources
  into the unified event schema and existing panels render them.
- The console can change its storage backend (DuckDB → OpenSearch) without the collector or
  ingester knowing.
- A new cloud (Azure, GCP) reuses the EPF and the unified schema; the console never learns
  provider-specific logic.

## Tier responsibilities

### Collector (`collector/`)
- Runs in the client's cloud shell under their reviewed read-only IAM policy.
- One module per artifact group; pure where possible (clients in → records out).
- Hashes each source on acquisition, builds the manifest, seals + signs the package.
- Ships nothing on its own beyond the operator-chosen transport.

### Ingester (`ingester/`)
- **Verify** signature + per-source SHA-256.
- **Parse** each source (one parser per type, independently versioned).
- **Normalize** to the unified event schema; preserve the original under `raw`.
- **Enrich** (IP geo/ASN, user-agent class, IOC match) — additive only.
- **Load** to the case store. Default DuckDB-on-Parquet; OpenSearch optional.

### Console (`console/`)
- **Backend** (FastAPI): thin query layer over the case store; RBAC enforced server-side.
- **Frontend** (Next.js): the analyst GUI. One module per panel. URL-addressable state.
- No outbound calls; all assets shipped locally; telemetry off by default.

## Why three tiers and not one binary

- The collector must stay tiny and auditable so a client will paste it. Heavy deps
  (pandas, DuckDB, a web stack) have no place in the cloud shell.
- The ingester carries the heavy normalization deps and can be updated without re-shipping
  anything to clients.
- The console stays a thin reader, so a case can be re-ingested (new parser version) without
  touching the UI, and the storage backend can change without rewriting the frontend.
