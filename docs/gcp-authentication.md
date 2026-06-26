# GCP authentication for Ventra

Ventra does not authenticate from the Acquire console. Collection runs on the client or IR
host via an **acquisition kit** (`ventra.py`). The kit holds scope (project IDs, collectors,
time window). **Credentials never go inside the kit zip.**

## What you need

1. A **read-only service account** with permissions from `docs/iam-policies/gcp-collector-readonly.json` (the kit includes a narrowed copy under `iam/`).
2. That role granted on **every project** you intend to collect (or at folder/org scope).
3. A **project list** in `acquisition.yaml` (from Acquire) or on the command line.
4. A **service account JSON key** on disk, unless you run on Cloud Shell or a VM with the SA attached.

Authentication (who) and scope (which projects) are separate:

| Input | Purpose |
|-------|---------|
| `--credentials PATH` or `GOOGLE_APPLICATION_CREDENTIALS` | Who is calling GCP |
| `--project` or `project` in `acquisition.yaml` | Which projects to query |

If you omit `--project`, Ventra falls back to the **home project** embedded in the service account key. For multi-project IR, always list projects explicitly.

## Running the kit

```bash
python3 ventra.py \
  --project client-proj-a,client-proj-b \
  --credentials /secure/ventra-collector-sa.json \
  --out ./ventra-evidence
```

Alternatives to `--credentials`:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/secure/ventra-collector-sa.json
python3 ventra.py --out ./ventra-evidence
```

Project IDs can come from `acquisition.yaml` instead of `--project` when the IR lead set them in Acquire.

## Scenarios

### Client runs the kit themselves

1. Admin creates service account `ventra-collector@...`.
2. Admin grants the read-only role on in-scope projects.
3. Admin generates a JSON key (or uses GCP Cloud Shell with an attached service account).
4. Operator runs:

```bash
python3 ventra.py --credentials ./ventra-sa.json --out ./evidence
```

### IR runs the kit on the client's behalf

1. Client creates the service account and role (security review of `iam/` in the kit).
2. Client sends the JSON key through a secure channel (not email or chat).
3. IR saves the key outside the kit directory and runs with `--credentials`.
4. IR deletes the key file when the engagement ends; client rotates or deletes the key.

Avoid `gcloud auth login` for IR-led collection — that ties the run to a human Google account instead of a dedicated collector principal.

### Cloud Shell or GCE with attached service account

No JSON key file required. Open Cloud Shell in the client project, upload the kit, and run:

```bash
python3 ventra.py --out ./evidence
```

Identity comes from the Cloud Shell user or the VM's attached service account (Application Default Credentials).

## Client setup checklist

1. Create service account in any admin project.
2. Create custom role from `gcp-collector-readonly.json` (or equivalent predefined roles).
3. Bind role on each target project (or folder/org).
4. Enable APIs: Cloud Logging, Cloud Resource Manager; Security Command Center if using SCC collectors.
5. Generate JSON key only if key-based auth is allowed by policy.
6. Build kit in Acquire with project ID(s) and selected collectors.

## Security notes

- Never embed JSON keys in the kit zip or `acquisition.yaml`.
- Prefer a dedicated collector service account, not a person's user account.
- Rotate or delete keys after the engagement.
- The package manifest records the service account email (principal), not the key material.

## Reference

| Flag / env | GCP equivalent of |
|------------|-------------------|
| `--credentials` | AWS `--profile` / access keys file |
| `--project` | Account / subscription scope |
| `GOOGLE_APPLICATION_CREDENTIALS` | Same as `--credentials` |

Full IAM policy: [`docs/iam-policies/gcp-collector-readonly.json`](iam-policies/gcp-collector-readonly.json)
