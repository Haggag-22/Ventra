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

## Scale caps (current)

Ventra today targets single-engagement triage, not always-on log warehousing. Two limits to
know about:

- **~200,000 records per source.** Log-based collectors stop at ~200k records per source and
  mark the source `partial` (the cap is recorded in the source `_meta.json`). Narrow the
  `--since` / `--until` window to capture a denser slice of a busy log.
- **4 GB console upload cap.** The analyst console rejects evidence packages larger than 4 GB
  on import. Split very large collections by time window or by collector pack.

Neither is a hard blocker for incident triage — they bound memory and disk on a workstation.
Streaming transport (S3) and bulk ingest that lift both caps are tracked as Phase 4 work.
