# Analyst Runbook — investigating in the Ventra console

For the **investigator / analyst** working a case in the console. The console runs on your
IR workstation (or forensic VPC) and makes no outbound calls.

## 1. Start the console

```bash
ventra gui        # http://localhost:8080  (hot reload; first run sets up .venv + npm)
```

No Docker — a packaged desktop app is planned for the v1 release. To run the pieces by hand
during development, see [`console/README.md`](../../console/README.md).

## 2. Import the evidence package

In **Cases → Import package**, drop the `.tar.zst`. Ventra will, in order:

1. **Verify** the signature and every per-source SHA-256.
2. **Parse** each source.
3. **Normalize** records into the unified event schema.
4. **Load** into the case store (DuckDB/Parquet by default).

If integrity fails, the import stops and shows exactly which hash/signature mismatched. A
clean import shows a **green integrity badge** on the case header.

> Prefer the CLI? `ventra-ingest ./case-....tar.zst --case-store ./cases`

## 3. Orient — the Overview panel

Open the case. The **Overview** gives you:

- Account context, time window, regions touched, operator who collected it.
- **Collection completeness** — which sources came back collected / empty / missing, and
  why. *Read this first.* A disabled Tier 1 source changes how you interpret everything else.
- Quick stats and suggested starting points (auto-generated from findings).

## 4. Investigate — recommended flow

The panels are ordered for a typical investigation, top to bottom:

1. **Findings** — triage GuardDuty / Security Hub / Inspector / Macie. Pivot from any finding.
2. **Timeline** — put everything on one axis. Brush to the incident window. Filter by source,
   principal, IP, region.
3. **CloudTrail Analyzer** — the control-plane deep dive. Use saved views: *Root activity*,
   *AccessDenied storm*, *Console logins from new IPs*, *Sensitive IAM/KMS/Secrets actions*.
4. **Identity** — who the principals are, key hygiene, and the **role-assumption graph**
   (who assumed what). Lateral movement lives here.
5. **Network** — VPC flow top talkers, egress-to-public volume (the exfil lens), DNS, WAF.
6. **Resources** — what was created / modified / made public / shared **during the window**.
   EBS snapshot share+copy history is a classic exfil tell.

## 5. Pivot everywhere

Every IP, principal, ARN, and resource ID is clickable. The **Pivot** menu jumps to that
entity's slice in every other panel with the filter pre-applied. This is the fastest way to
follow a thread: see a suspicious IP in Findings → pivot to Timeline → pivot to Identity.

## 6. Build the report

In **Report**, pin events, charts, and findings as you go (every row has a *Pin to report*
action). Pinned items render as immutable evidence callouts with their hash and source
reference. Export to PDF / DOCX / Markdown.

## 7. Share views, not screenshots

Every filter and selection is in the URL. Send a colleague a link to the exact Timeline
range and filter set you're looking at — they open the same case at the same view.

## Keyboard

`⌘K` command palette · `/` focus search · `j`/`k` move selection · `g t` Timeline ·
`g c` CloudTrail · `g i` Identity · `g n` Network · `g r` Resources · `g f` Findings.
