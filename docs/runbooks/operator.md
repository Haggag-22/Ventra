# Operator Runbook — running the Harbor collector

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

CloudShell already has credentials for the signed-in principal. From the shell:

```bash
pip install --user harbor-collector

harbor-collect aws \
  --case CASE-2026-0042 \
  --since 2026-05-11 \
  --regions us-east-1,us-west-2 \
  --out ./harbor-evidence
```

The collector prints a live progress table, then writes a sealed package:

```
./harbor-evidence/case-CASE-2026-0042-123456789012-20260610T181530Z.tar.zst
./harbor-evidence/case-CASE-2026-0042-...-.tar.zst.sig
```

> **CloudShell limits.** Home is ~1 GB and the session idles out after ~20 min. For large
> S3-resident logs, pass `--stream-to s3://your-evidence-bucket/...` (a bucket *you* control)
> so big pulls stream out instead of staging locally. See `--help`.

Harbor runs **every registered collector** on each invocation — there are no profiles to
choose. Analysts review what came back (and what surfaced as gaps) in the console. Use
`harbor-collect aws --list-collectors` to see the current set.

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
cosign verify-blob --key harbor-release.pub \
  --signature harbor-collector.whl.sig harbor-collector.whl
```
