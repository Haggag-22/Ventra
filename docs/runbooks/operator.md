# Operator Runbook — running a collection

For the **responder** running a collection in the client's environment (or the client running
it themselves under your guidance). Collection is read-only and Ventra sends nothing outbound
on its own: the sealed package stays where it was written until you move it.

The flow is the same for every cloud:

1. Build a **Collection Kit** in the console.
2. Run it — from the console, or as a `.kit` file in a terminal.
3. Bring the sealed `.tar.zst` package back and import it under **Cases**.

## Before you start

1. **Get the permissions reviewed.** Send the client the read-only policy for their cloud
   from [`docs/iam-policies/`](../iam-policies/) (for AWS,
   [`aws-collector-readonly.json`](../iam-policies/aws-collector-readonly.json)). Their
   security team confirms it is read-only and grants it to the identity you will use.
   Downloaded kits also carry the policy for their selected sources in `iam/`.
2. **Agree a case ID and time window.** For example `CASE-2026-0042`, window = incident date
   minus 30 days. IR rarely wants everything; scope to the incident plus a buffer.
3. **Agree regions / projects / subscriptions** if you want to limit scope (default: all
   enabled regions).

## 1. Build the kit

Open the console with `ventra gui` (`http://127.0.0.1:8000`).

1. **Configuration → Authentication** — add a connection for the cloud you are collecting
   from, using the read-only identity above.
2. **Configuration → Acquire** — pick the cloud, add the log sources you want from the
   artifact library, name the kit, set **Since** / **Until** (and regions if agreed), then
   click **Save kit**.

The kit now appears under **Collection Kits**.

## 2. Run the kit

### Option A: from the console (AWS, Azure, GCP)

In **Collection Kits**, click **Run**, choose a new or existing case and the connection to use.
The console shows live progress and imports the package into the case when the run finishes.
Nothing to carry back — skip to [What "gaps" mean](#what-gaps-mean).

### Option B: from a terminal (all clouds; the only option for Kubernetes)

In **Collection Kits**, click **Download Kit** and choose the connection to embed. Copy the
`.kit` file (named after the kit) to the machine that should do the collection and run:

```bash
ventra run my-kit.kit
```

The run prints live progress and writes a sealed package to `./evidence` (change it with
`--out`):

```
./evidence/case-CASE-2026-0042-123456789012-20260610T181530Z.tar.zst
./evidence/case-CASE-2026-0042-123456789012-20260610T181530Z.tar.zst.sha256
```

The package's signed manifest (`manifest.json` + `manifest.json.sig`) is **inside** the
`.tar.zst`; there is no separate signature file to carry.

> **A `.kit` file contains working credentials.** Treat it like a password: send it over a
> secure channel, don't commit it, and delete it when the collection is done. Kits expire,
> and `ventra run` refuses to run an expired kit.

On a Kubernetes node, `ventra run` re-runs itself with `sudo` so it can read root-only log
files. Pass `--no-sudo` to skip that; those sources are then recorded as gaps.

#### Running a kit in AWS CloudShell

CloudShell needs no local setup. Install Ventra (safe to re-run every session; it upgrades
to the latest release with `uv tool install` into `~/.local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
```

Upload the `.kit` file (**Actions → Upload file**), then run it:

```bash
ventra run my-kit.kit
```

When it finishes, download the `.tar.zst` from `./evidence` (**Actions → Download file**).

> **CloudShell limits.** Home is ~1 GB and the session idles out after ~20 min. Large
> S3-resident sources (VPC Flow Logs in buckets, CloudTrail archives, big access-log prefixes)
> can fill the disk or outlast the session. For multi-GB pulls, run the kit on an EC2
> instance instead.

## 3. Bring the package back and import it

Move the `.tar.zst` to the analyst workstation over your secure channel, check its SHA-256
against the `.sha256` file written next to it, then import it in the console with
**Cases → Import package**. Import verifies the manifest signature and every per-source hash
before loading anything.

From a terminal, `ventra-verify <package>` checks the same hashes and seal without importing.

## What "gaps" mean

If a source comes back as a **gap** (e.g. `vpc_flow: logging_not_configured`), that is
expected and useful — it tells the IR team the log didn't exist or wasn't readable, not that
collection failed. Don't try to "fix" it; the gap is recorded in the manifest as evidence and
shows up in **Logs Coverage**.

`partial` on a log source means a real gap (access denied, logging off, or an optional record
cap) — check the manifest gaps and the Collection panel.

## Scale

Ventra collects **every record in the kit's Since / Until window** by default. Collection may
be slow on busy accounts — that is expected.

Practical limits:

- **CloudShell ~1 GB home** — run large collections on EC2 (see above).
- **Console import** — default ~20 GB package cap (`VENTRA_MAX_UPLOAD_MB`).
- **Posture / inventory collectors** (IAM snapshots, log-posture scans) sample resource
  lists — they are not time-series logs.

An optional per-source triage cap, `max_records_per_source`, can be set in the kit's
`acquisition.yaml` to stop early.

---

## Advanced: CLI collection

`ventra collect` runs collectors directly from flags, without a kit. It is useful for
scripting and testing; for engagements, prefer a kit so the scope is reviewed in Acquire and
recorded with the package.

```bash
ventra collect aws \
  --case CASE-2026-0042 \
  --since 2026-05-11 \
  --regions us-east-1,us-west-2 \
  --out ~/ventra-evidence
```

- Clouds: `aws`, `azure`, `gcp`, `kubernetes`. `ventra collect <cloud> --help` lists each
  cloud's auth flags.
- Every registered collector runs unless you pass `--collectors`, `--pack`, or
  `--acquisition <acquisition.yaml>`. See them with `--list-collectors` / `--list-packs`.
- The package is imported into a local case store afterwards, except in CloudShell; pass
  `--no-ingest` to skip that anywhere.

`--transport` delivers the finished package (`ventra run` always writes locally):

- **`local`** (default) — write to disk; hand-carry or upload through your secure channel.
- **`s3://bucket/prefix/`** — upload to an S3 bucket you control.
- **`s3-presigned:<url>`** — upload to a presigned URL the IR team gives you.
- **`sftp:user@host:/path`** — push to an SFTP drop.

Always confirm the package's SHA-256 matches what the IR team receives.
