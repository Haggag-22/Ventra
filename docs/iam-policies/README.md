# Ventra read-only IAM policies

The collector is **strictly read-only**. These policies contain only describe/get/list
actions — no `Create*`, `Put*`, `Delete*`, `Update*`, `Modify*`, `Run*`, `Terminate*`, or
other mutating verbs. The CI `readonly-guard` check enforces this against the collector code.

## How to use

Give the policy to the client's security team to review **before** they run anything. Attach
it to the role the responder will assume in the client account, or to a dedicated
`VentraCollector` role.

| File | Scope |
|------|-------|
| [`aws-collector-readonly.json`](aws-collector-readonly.json) | All Tier 1 + Tier 2 AWS collectors. |
| [`gcp-collector-readonly.json`](gcp-collector-readonly.json) | All GCP collectors. See [`../gcp-authentication.md`](../gcp-authentication.md) for kit auth. |

For a Tier-1-only engagement you can trim the `VentraTier2ReadOnly` and
`VentraReadLogObjects` statements.

## Why some `s3:GetObject` is required

CloudTrail, VPC Flow Logs, ELB/CloudFront access logs, and WAF logs are frequently delivered
to S3 rather than CloudWatch. To collect them, the policy grants `s3:GetObject` /
`s3:ListBucket` **scoped to common log-bucket name patterns** (`*-logs`, `*cloudtrail*`,
`*flow-log*`). If the client's log buckets use a different naming convention, edit the
`VentraReadLogObjects` resource list accordingly — and document the change in the case notes.

## Verifying read-only

```bash
# Lists every action in the policy and flags any that are not get/list/describe/lookup.
python -m collector.tools.verify_readonly docs/iam-policies/aws-collector-readonly.json
```
