# Harbor live-test harness

A one-command test cycle that stands up a small, **deliberately misconfigured** AWS
environment, enables the detection services, generates real activity (sample findings +
optional Stratus Red Team attacks), runs `harbor-collect`, and then tears everything back
down. The point is to exercise all 16 collectors against real AWS responses — the one thing
the moto test suite can't prove.

> ⚠️ **This costs money and creates attacker-looking activity. Use a dedicated throwaway /
> sandbox account only — never production, never anything shared.**

## What it deploys (Terraform → real but cheap resources)

| Collector exercised | Resource created |
|---|---|
| `iam` | A user with an access key + over-broad inline policy, an assumable role |
| `s3` | A `*-logs` bucket, a bucket with public-access-block **disabled**, a bucket with synthetic PII |
| `kms` | A customer-managed key + alias |
| `secrets` | A Secrets Manager secret (metadata only is collected — never the value) |
| `lambda` | A no-op function with secret-looking env vars (collector redacts them) |
| `ec2` | A `t3.micro` with a fake-secret in user-data, an EBS volume + snapshot, an open (0.0.0.0/0:22) security group |
| `vpc_flow` | A VPC with Flow Logs → CloudWatch (no NAT gateway, to avoid cost) |
| `config` | *(optional, `enable_config=true`)* a Config recorder + delivery channel |

## What it enables / generates (CLI, in `run-test.sh`)

| Collector exercised | Action |
|---|---|
| `guardduty` | Creates a detector if none, then `create-sample-findings` (real findings, no attack needed) |
| `securityhub` | `enable-security-hub` + default standards (findings appear from the misconfigs within ~1h) |
| `macie` | *(optional, `WITH_MACIE=1`)* `enable-macie` + a classification job on the PII bucket |
| `cloudtrail`, `sts` | *(optional, Stratus)* detonates a few MITRE ATT&CK techniques → real CloudTrail + GuardDuty data |

`detective` is intentionally left disabled by default (it's the priciest service and needs
GuardDuty running ~48h first). Leaving it off also lets you verify the collector's
"service not enabled" gap path, which is itself valid evidence.

## Prerequisites

- `aws` CLI v2, authenticated to your **sandbox** account (`aws sts get-caller-identity`)
- `terraform` >= 1.3
- `harbor-collect` on PATH (`pip install -e .` from the repo root)
- *(optional)* `stratus` — [Stratus Red Team](https://github.com/DataDog/stratus-red-team). If
  absent, the attack step is skipped with a notice.
- *(optional)* `jq` — for the gap summary at the end.

## Usage

```bash
cd scripts/live-test

# Stand up + enable services + generate findings + (optional) attack + collect:
bash run-test.sh                 # interactive: prints the account and asks you to confirm
bash run-test.sh -y              # skip the confirmation prompt
WITH_STRATUS=1 bash run-test.sh  # also run the Stratus attack subset
WITH_MACIE=1   bash run-test.sh  # also enable Macie + run a PII classification job

# When you're done — ALWAYS run this (disables services, destroys infra, cleans Stratus):
bash teardown.sh
```

The sealed evidence package lands in `scripts/live-test/out/`. Open its `manifest.json` and
read the `sources` statuses and the `gaps` array — that's the real test result.

## Cost notes

- Biggest line items: **GuardDuty, Security Hub, Macie, Config**, and the **EC2 instance**.
  All are enabled→disabled / created→destroyed within the cycle, so a same-day run is a few
  dollars at most.
- **Set a budget alarm first.** Example:
  ```bash
  aws budgets create-budget --account-id "$(aws sts get-caller-identity --query Account --output text)" \
    --budget '{"BudgetName":"harbor-live-test","BudgetLimit":{"Amount":"20","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}'
  ```
- `teardown.sh` only disables the detection services **that this harness enabled** (tracked in
  `.state/`), so it won't turn off something you already had running.

## Safety model

Terraform creates *inventory + benign misconfigurations* only. The genuinely dangerous
exposures (publicly shared EBS snapshot, public bucket policy) are produced by **Stratus**,
which manages and reverts them with its own `cleanup` — so nothing dangerous is left standing
between runs. The `make_*_public` Terraform toggles default to `false`.

All secrets/passwords in user-data, env vars, and the PII file are **synthetic** and clearly
marked as fake.
