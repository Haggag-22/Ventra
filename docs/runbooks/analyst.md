# Analyst Runbook — investigating in the Ventra console

For the **investigator / analyst** working a case in the console. The console runs on your
IR workstation (or forensic VPC) and makes no outbound calls.

## 1. Start the console

```bash
ventra gui        # opens http://127.0.0.1:8000 (or the next free port)
```

No Docker or Node.js needed: the console ships inside the `ventra` package. To work on the
console itself from a checkout, see [`console/README.md`](../../console/README.md).

## 2. Import the evidence package

In **Cases → Import package**, drop the `.tar.zst`. Ventra will, in order:

1. **Verify** the manifest seal and every per-source SHA-256.
2. **Parse** each source.
3. **Normalize** records into the unified event schema.
4. **Load** into the case store (DuckDB/Parquet by default).

The case header shows the result:

- **Sealed · advisory** (amber) — every hash matched, and the manifest carries a SHA-256
  stamp. This is the normal result: it proves nothing changed in transit, but it is not
  key-backed. A cosign/minisign signature also shows amber until you verify it yourself with
  the signer's public key (`cosign verify-blob` / `minisign -V`).
- **Integrity failed** (red) — a hash or the stamp did not match, or the package is unsealed.
  The integrity view lists exactly which file failed.

> Prefer the CLI? `ventra-ingest ./case-....tar.zst --case-store ./cases`

## 3. Orient — Logs Coverage first

Cases open on the control-plane timeline (CloudTrail / Activity Log / Audit Log). Before
drawing conclusions, open **Logs Coverage**:

- Which collectors came back collected, partial, empty, denied, or not run.
- Manifest **gaps** (for example VPC Flow Logs not enabled) — missing telemetry is evidence.
- A disabled Tier 1 source changes how you interpret everything else.

## 4. Investigate — recommended flow

Sidebar panels (Investigate, then Package), top to bottom for a typical case:

1. **Security Findings** — triage GuardDuty / Security Hub / Inspector / Macie / Detective /
   Config (AWS), Defender (Azure), or SCC / Cloud Monitoring (GCP). Pivot from any finding.
2. **CloudTrail Timeline** (Azure: **Activity Log**; GCP: **Audit Log**) — control-plane
   deep dive. Filter by source, action, principal, IP, region, and (AWS) trail category
   (management / data / insight / network activity).
3. **CloudWatch Logs** (AWS only) — selected log group events when domain collectors did not
   cover the evidence you need.
4. **Identity & Access** — users, roles, groups, policies, MFA/key hygiene, plus KMS and
   Secrets inventory when those collectors ran.
5. **Network Activity** — VPC / VNet / NSG / firewall flow volume and egress-to-public
   (the exfil lens). DNS and WAF live on **Web & DNS**, not here.
6. **Web & DNS** — edge access logs, WAF verdicts, and DNS resolver queries.
7. **Data Access** — object-level and secret access (S3 / storage / Key Vault / GCS /
   BigQuery / Cloud SQL / Secret Manager, depending on cloud).
8. **Kubernetes Audit** — EKS / AKS / GKE API-server audit when those collectors ran.
9. **Resource Inventory** — EC2 / S3 / Lambda / ARM / GCE inventory; EBS snapshot
   share+copy history is a classic exfil tell on AWS.
10. **Raw Evidence** — browse sealed source files from the package when you need the
    original bytes.

## 5. Pivot everywhere

Every IP, principal, ARN, and resource ID is clickable. The **Pivot** menu jumps to that
entity's slice in every other panel with the filter pre-applied. This is the fastest way to
follow a thread: see a suspicious IP in Findings → pivot to the timeline → pivot to Identity.

## 6. Pin evidence

Use **Pin to report** on events and findings as you go. Pinned items stay on the case as
immutable evidence callouts with their source reference (see the Report route when you need
the pin list assembled).

## 7. Share views, not screenshots

Every filter and selection is in the URL. Send a colleague a link to the exact timeline
range and filter set you're looking at — they open the same case at the same view.

## Keyboard

`⌘K` / `Ctrl+K` command palette · `/` open palette · `g` then:

| Key | Panel |
|-----|--------|
| `t` or `c` | CloudTrail Timeline / Activity Log / Audit Log |
| `f` | Security Findings |
| `i` | Identity & Access |
| `n` | Network Activity |
| `a` | Logs Coverage |
