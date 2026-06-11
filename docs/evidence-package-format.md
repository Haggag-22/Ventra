# Evidence Package Format (EPF) v1

The EPF is the **single contract** between Harbor's three tiers. The collector produces it;
the ingester consumes it; the console renders from what the ingester loaded. Lock this and
the collector, ingester, and console can all evolve independently behind it.

> Schemas: [`schemas/manifest.schema.json`](../schemas/manifest.schema.json),
> [`schemas/package.schema.json`](../schemas/package.schema.json),
> [`schemas/unified-event.schema.json`](../schemas/unified-event.schema.json).

## 1. Container

A package is a **zstandard-compressed tar archive**:

```
case-<case_id>-<account_id>-<utc-timestamp>.tar.zst
```

Example: `case-CASE-2026-0042-123456789012-20260610T181530Z.tar.zst`

zstd is chosen for high ratio and fast decompression on the analyst side. If `zstandard`
is unavailable in the client's cloud shell, the collector transparently falls back to gzip
(`.tar.gz`); the ingester accepts both.

## 2. Layout

```
manifest.json                 chain-of-custody, integrity, environment  (REQUIRED)
manifest.json.sig             detached signature over manifest.json       (REQUIRED)
collection.log                JSON-lines log of the collector run         (REQUIRED)
sources/
  <source>/                   one directory per logical source
    events.jsonl.zst          source records as JSON Lines (zstd)
    config.json               service / logging configuration snapshot
    _meta.json                window, regions, record_count, sha256
errors/
  <source>.log                partial failures, AccessDenied detail       (if any)
```

A "source" is a logical artifact group: `cloudtrail`, `vpc_flow`, `guardduty`, `waf`,
`iam`, `sts`, `account`, etc. Not every source emits all three files — an inventory source
(`iam`) emits `snapshot.json`; an event source (`cloudtrail`) emits `events.jsonl.zst`.

## 3. Manifest

Validated against `manifest.schema.json`. Required top-level fields:

| Field | Meaning |
|-------|---------|
| `schema_version` | EPF/manifest schema semver. |
| `tool_version`, `tool_commit` | Collector build provenance. |
| `case_id`, `engagement_id` | Operator-supplied identifiers. |
| `cloud`, `account_id`, `account_alias`, `org_id`, `partition`, `regions[]` | Environment. |
| `operator` | IAM principal ARN that ran the collector, user id, source IP. |
| `started_at`, `completed_at` | RFC 3339 UTC bounds of the run. |
| `time_window` | Incident window applied to event sources (`since`/`until`/`full_available`). |
| `profile` | Which profile ran, plus per-run overrides. |
| `sources[]` | Per source: `name`, `path`, `record_count`, `bytes`, `sha256`, `status`, `notes`. |
| `gaps[]` | Sources expected but unavailable, with a `reason`. **A gap is evidence.** |
| `host` | `cloudshell` / `ec2` / `local`, OS, runtime. |

## 4. Integrity flow

```
   acquire            seal                 transit              import
 ┌─────────┐      ┌──────────┐          ┌──────────┐        ┌──────────┐
 │ SHA-256 │ ───► │ manifest │ ──sign──►│  .tar.zst│ ─────► │  verify  │
 │ per file│      │ records  │          │  shipped │        │ hash+sig │
 └─────────┘      └──────────┘          └──────────┘        └──────────┘
```

1. **On acquisition** the collector hashes each source file (SHA-256) *before it leaves the
   source account* and records the digest in `manifest.sources[].sha256`.
2. The completed `manifest.json` is **signed** → `manifest.json.sig` (cosign or minisign).
3. **On import** the ingester recomputes every hash and verifies the signature. Any mismatch
   blocks the load and is written to the case's integrity report.
4. The console shows a **green / amber / red integrity badge** on the case header. Amber =
   optional source missing; red = hash or signature mismatch.

## 5. Source record format

Inside `events.jsonl.zst`, each line is one source record **as collected** — Harbor does
*not* normalize inside the package. Normalization happens in the ingester so that the raw
evidence in the package stays as close to the provider's original as possible. The ingester
maps these into the unified event schema at import.

Rationale: keeping the package raw means a third party can verify the evidence against the
provider's own export without trusting Harbor's normalization.

## 6. Versioning

`schema_version` is semver:

- **Patch** — clarifications, new optional fields. Older ingesters keep working.
- **Minor** — new optional sources or manifest fields. Forward compatible.
- **Major** — breaking change. The ingester declares the major versions it supports and
  refuses (with a clear message) anything outside that range.

## 7. Example manifest (abridged)

```json
{
  "schema_version": "1.0.0",
  "tool_version": "0.1.0",
  "case_id": "CASE-2026-0042",
  "cloud": "aws",
  "account_id": "123456789012",
  "account_alias": "client-prod",
  "regions": ["us-east-1", "us-west-2"],
  "operator": {
    "principal_arn": "arn:aws:sts::123456789012:assumed-role/IR-Responder/omar",
    "source_ip": "203.0.113.10"
  },
  "started_at": "2026-06-10T18:15:30Z",
  "completed_at": "2026-06-10T18:22:04Z",
  "time_window": { "since": "2026-05-11T00:00:00Z", "until": null, "mode": "window" },
  "profile": { "name": "baseline", "overrides": [] },
  "sources": [
    { "name": "cloudtrail", "path": "sources/cloudtrail/events.jsonl.zst",
      "record_count": 48213, "bytes": 19283742,
      "sha256": "9f2c...e1", "status": "collected" }
  ],
  "gaps": [
    { "name": "vpc_flow", "reason": "logging_not_configured",
      "detail": "No flow logs configured on any VPC in us-east-1 / us-west-2." }
  ],
  "host": { "environment": "cloudshell", "os": "Amazon Linux 2023", "runtime": "python 3.11.8" }
}
```
