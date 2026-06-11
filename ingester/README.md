# Harbor Ingester

Turns a sealed [evidence package](../docs/evidence-package-format.md) into a queryable case
the console can investigate. Runs on the IR workstation — heavy deps live here, not in the
collector.

## Pipeline

```
.tar.zst ──► verify ──► parse ──► normalize ──► enrich ──► load ──► case store
            sig+hash   per src   unified evt    ip/ua/ioc  parquet  cases/<id>/
```

1. **Verify** — detached signature + every per-source SHA-256 against the manifest. Failures
   block the load and are written to the case's integrity report.
2. **Parse** — one parser per source (`parsers/`). Pure: package file in, records out.
3. **Normalize** — map to the unified event schema (`normalizer/`). The original record is
   preserved verbatim under `raw`.
4. **Enrich** — additive only: IP geo/ASN, user-agent class, IOC match. Never touches `raw`.
5. **Load** — write normalized events to Parquet and build the per-case indexes the console
   reads. Default store is DuckDB-over-Parquet; OpenSearch is an optional loader.

## Use

```bash
harbor-ingest ./case-CASE-2026-0042-*.tar.zst --case-store ./cases
harbor-verify ./case-CASE-2026-0042-*.tar.zst          # integrity check only
```

## Case store layout

```
cases/<case_id>/
  manifest.json        copy of the package manifest
  integrity.json       verification report (per-source hash results, signature method)
  summary.json         precomputed Overview stats (counts, top principals/IPs, gaps)
  events.parquet       all normalized events (unified schema, flattened columns)
  inventory/*.json     raw snapshots: iam, ec2, s3, kms, secrets, account, ...
```

The console backend queries `events.parquet` with DuckDB and reads `summary.json` /
`inventory/` directly. Re-ingesting a package rebuilds the case store without touching the UI.
