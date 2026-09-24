# {{KIT_NAME}}

Ventra acquisition kit for **read-only** evidence collection. Unzip this folder on the
collection host (workstation, Cloud Shell, jump box, or Kubernetes node), run the entry
script once, then send the sealed evidence package back to your IR team.

---

## Quick start

```bash
# 1. Unzip (example)
unzip "{{KIT_ZIP}}" -d "{{KIT_SLUG}}" && cd "{{KIT_SLUG}}"

# 2. Collect (credentials are already embedded when downloaded with Authentication)
python3 {{ENTRY_SCRIPT}} --out ./evidence

# Same thing via the shell wrapper:
./run.sh --out ./evidence
```

What you get:

- A folder named `evidence/` **next to** `{{ENTRY_SCRIPT}}`
- Inside it, a sealed `.tar.zst` package for Ventra **Cases → Import package**

First run installs a local `.venv` (via **uv**) and the bundled wheel in `dist/`. Needs
Python **3.11+**. Network is only needed if `uv` itself is missing; the Ventra package
comes from `dist/`.

---

## What is in this kit

| Path | Purpose |
|------|---------|
| `{{ENTRY_SCRIPT}}` | Main entry point — run this |
| `run.sh` | Thin wrapper that calls `{{ENTRY_SCRIPT}}` |
| `acquisition.yaml` | Case id, cloud, collectors, time window, scope |
| `credentials/` | Embedded Authentication connection (do not email separately) |
| `artifacts/` | Selected collector definitions |
| `iam/` | Read-only IAM / RBAC policy references for this kit |
| `dist/` | Bundled `ventra` wheel (offline install) |
| `requirements.txt` | Bootstrap dependencies |
| `deployment-profile.txt` | Why this deployment profile was chosen |

---

## After collection

1. Locate the sealed package under `./evidence/` (or the `--out` path you chose).
2. Transfer it over your secure evidence channel (do **not** put cloud secrets in the zip).
3. Analyst imports it in Ventra: **Cases → Import package**.
4. Export / Investigate features work after import.

---

## Common options

```bash
python3 {{ENTRY_SCRIPT}} --out ./evidence
python3 {{ENTRY_SCRIPT}} --help
```

| Flag | What it does |
|------|----------------|
| `--out DIR` | Evidence folder next to the script (default: `evidence`) |
| `--profile NAME` | AWS named profile (only if not already embedded) |
| `--subscription ID` | Azure subscription override |
| `--project ID` | GCP project override |
| `--credentials PATH` | GCP service-account JSON (only if not embedded) |

Cloud, collectors, and auth usually come from `acquisition.yaml` + `credentials/`. You
normally do **not** need extra flags when the kit was downloaded with an Authentication
connection selected.

**After downloading a newer kit into the same folder**, clear the old venv so deps refresh:

```bash
rm -rf .venv
python3 {{ENTRY_SCRIPT}} --out ./evidence
```

---

## Cloud notes

### AWS

- Prefer an embedded connection, or `--profile` / `AWS_PROFILE` with the role in `iam/`.
- Attach only the narrowed actions from `iam/` — not AdministratorAccess.

### Azure

- Embedded connection covers tenant/client when present.
- If you use an app secret, set it in the environment only (never in the zip):

```bash
export AZURE_CLIENT_SECRET='…'
python3 {{ENTRY_SCRIPT}} --out ./evidence
```

- Apply the custom role / Graph permissions in `iam/` before collecting.

### GCP

- Embedded service-account JSON is preferred when the connection includes it.
- Otherwise: `--credentials /secure/sa.json` or `GOOGLE_APPLICATION_CREDENTIALS`.
- Scope projects with `--project` or the `project` field in `acquisition.yaml`.

### Kubernetes

1. Apply the ClusterRole from `iam/kubernetes-collector-readonly.yaml` (not `cluster-admin`).
2. Download the kit with that Authentication connection — kubeconfig is embedded.
3. Run on a host that can reach the API:

```bash
python3 {{ENTRY_SCRIPT}} --out ./evidence
```

4. **Node-plane collectors** (container / CRI / kubelet / etcd / apiserver audit logs) must
   run **on the node** (SSH as root, or the DaemonSet / Job under `deploy/kubernetes/` in
   the Ventra repo). API-plane collectors only need kubeconfig.

Control-plane paths differ by distribution (kubeadm, k3s, RKE2, managed EKS/GKE/AKS).
Gaps on workers or managed control planes are expected; check `config.json` inside the
evidence package for paths tried.

---

## Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `python3: command not found` | Install Python 3.11+ on the host |
| Permission / 403 / AuthorizationFailed | Confirm `iam/` role is attached; re-test Authentication in Ventra |
| Empty / missing node logs (Kubernetes) | Run on the node itself, not only from a laptop kubeconfig |
| Stale behavior after a new download | `rm -rf .venv` then re-run |
| Empty `dist/` | Rebuild the kit from the console (Acquire always bundles a wheel) |

---

## Security

- This kit is **read-only** collection. Do not grant write / admin roles “to make it work”.
- Treat `credentials/` as sensitive — same handling as a cloud key or kubeconfig.
- Evidence leaves the environment only via your agreed transfer channel.
