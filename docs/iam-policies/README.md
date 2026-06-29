# Ventra read-only IAM policies

The collector is **strictly read-only**. These policies contain only describe/get/list
actions — no `Create*`, `Put*`, `Delete*`, `Update*`, `Modify*`, `Run*`, `Terminate*`, or
other mutating verbs. The CI `readonly-guard` check enforces this against the collector code.

## How to use

Give the policy to the client's security team to review **before** they run anything.

| File | Scope |
|------|-------|
| [`aws-collector-permissions.txt`](aws-collector-permissions.txt) | AWS — collector + read-only actions (send to IAM admin; they assign Resource ARNs). |
| [`gcp-collector-permissions.txt`](gcp-collector-permissions.txt) | GCP — collector + read-only permissions (they assign project/resource scope). |
| [`aws-collector-readonly.json`](aws-collector-readonly.json) | AWS reference IAM policy. Labs / quick validation. |
| [`gcp-collector-readonly.json`](gcp-collector-readonly.json) | GCP reference permission list. |
| [`azure-collector-readonly.json`](azure-collector-readonly.json) | Azure ARM read-only. |
| [`azure-collector-graph.json`](azure-collector-graph.json) | Microsoft Graph (Entra). |
| [`azure-collector-m365.json`](azure-collector-m365.json) | M365 Unified Audit Log search. |

## Verifying read-only

```bash
python -m collector.tools.verify_readonly docs/iam-policies/aws-collector-readonly.json
```
