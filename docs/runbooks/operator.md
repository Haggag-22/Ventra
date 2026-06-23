# Operator Runbook — running the Ventra collector

For the **responder** running the collector in the client's environment (or the client
running it themselves under your guidance). The collector is read-only and ships nothing
outbound on its own.

## Before you start

1. **Get the IAM policy reviewed.** Send the client
   [`docs/iam-policies/aws-collector-readonly.json`](../iam-policies/aws-collector-readonly.json).
   Their security team confirms it's read-only and attaches it to the role you'll use.
2. **Agree a case ID and time window.** e.g. `CASE-2026-0042`, window = incident date minus
   30 days. IR rarely wants everything; scope to the incident plus a buffer.
3. **Agree regions** if you want to limit scope (default: all enabled regions).

## Running in AWS CloudShell

CloudShell already has credentials for the signed-in principal.

### One-time setup (skips if Ventra is already installed)

```bash
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
```

This creates `~/.ventra-venv`, installs Ventra once, and adds it to your PATH. Re-running
the script is safe — it detects an existing install and does not re-download packages.

### Collect evidence

```bash
ventra collect aws \
  --case CASE-2026-0042 \
  --since 2026-05-11 \
  --regions us-east-1,us-west-2 \
  --out ~/ventra-evidence
```

Or install and collect in one step:

```bash
VENTRA_CASE=CASE-2026-0042 VENTRA_SINCE=2026-05-11 \
  bash bin/aws_cloudshell.sh
```

The collector prints a live progress table, then writes a sealed package:

```
./ventra-evidence/case-CASE-2026-0042-123456789012-20260610T181530Z.tar.zst
./ventra-evidence/case-CASE-2026-0042-...-.tar.zst.sig
```

> **CloudShell limits.** Home is ~1 GB and the session idles out after ~20 min. For large
> S3-resident logs, pass `--stream-to s3://your-evidence-bucket/...` (a bucket *you* control)
> so big pulls stream out instead of staging locally. See `--help`.

Ventra runs **every registered collector** on each invocation — there are no profiles to
choose. Analysts review what came back (and what surfaced as gaps) in the console. Use
`ventra collect aws --list-collectors` to see the current set.

## Shipping the package to the IR team

Transport options (`--transport`):

- **`local`** (default) — write to disk; you hand-carry / upload through your secure channel.
- **`s3-presigned`** — upload to a presigned URL the IR team gives you.
- **`sftp`** — push to an SFTP drop.

Always confirm the printed SHA-256 of the final package matches what the IR team receives.

## What "gaps" mean

If the collector reports a source as a **gap** (e.g. "vpc_flow: logging_not_configured"),
that is expected and useful — it tells the IR team the log didn't exist, not that collection
failed. Don't try to "fix" it; the gap is recorded in the manifest as evidence.

## Verifying before you run anything

```bash
cosign verify-blob --key ventra-release.pub \
  --signature ventra-collector.whl.sig ventra-collector.whl
```

## Scale (current)

Ventra collects **every record in the configured ``since`` / ``until`` window** by default
across AWS, Azure, and GCP log collectors. Collection may be slow on busy accounts — that is
expected.

Optional triage cap: set ``max_records_per_source`` to a positive integer in
``acquisition.yaml`` to stop early per source (legacy scoped pulls only).

Practical environment limits still apply:

- **CloudShell ~1 GB home** — stage large packages with ``--stream-to s3://...`` or run on EC2.
- **Console upload** — default ~20 GB package import cap (``VENTRA_MAX_UPLOAD_MB``).
- **Posture/inventory collectors** (IAM snapshots, log-posture scans) sample resource lists —
  they are not time-series logs.

``partial`` status on a **log source** means a real gap (access denied, logging off, or an
optional ``max_records_per_source`` cap) — check manifest gaps and the Collection panel.
