

> **Goal:** Stand up AWS infrastructure with every log source my tool checks, in both
> *logging-enabled* and *logging-disabled* states, then generate real activity so actual
> log content flows. Use this to validate the tool: no false positives when logging is on,
> and correct gap detection when logging is off.

---


Two phases:

1. **Phase 1 — Infrastructure + Logging** (Terraform): build resources, wire logging destinations.
2. **Phase 2 — Data Generation** (driver script): trigger every service so real logs land.

Plus a wrapping validation loop:
- `enable_logging = true`  → run tool → expect **full coverage** (no false positives)
- `enable_logging = false` → run tool → expect **all gaps caught**

---

## Phase 0 — Safe Sandbox (do first)

- [x] Create a **brand-new isolated AWS account** (or dedicated Org sub-account) — never production
- [x] Set a **Budget alert** ($20–30 threshold)
- [x] Pick **one region** (e.g. `us-east-1`) and keep everything there
- [x] Install **Terraform** locally
- [x] Install **infracost** (estimate cost before every apply)
- [x] Tag convention decided: `Project=logging-test`

---

## Phase 1 — Infrastructure + Logging (Terraform)

One Terraform project. Toggles:
- `enable_logging` (true/false) — flips logging state across all resources
- `enable_expensive` (true/false) — gates the pricey Tier 3 resources

### Tier 1 — Build FIRST (cheap, fast, ~free)

| Log Source             | "Logging ON" =                                   | "Logging OFF" =                       | Done |
| ---------------------- | ------------------------------------------------ | ------------------------------------- | ---- |
| CloudTrail             | Trail, multi-region, data events + Insights → S3 | No trail / data events + Insights off | [ ]  |
| AWS Config             | Recorder + delivery channel active → S3          | No recorder                           | [ ]  |
| VPC Flow Logs          | Flow log attached to VPC → S3/CW                 | VPC with no flow log                  | [ ]  |
| ELB/ALB Access Logs    | ALB `access_logs` enabled → S3                   | ALB access logs disabled              | [ ]  |
| S3 Access Logs         | Bucket server access logging → target bucket     | Bucket with no logging                | [ ]  |
| CloudFront Access Logs | Distribution logging config → S3                 | Distribution, logging off             | [ ]  |
| Lambda Logs            | Function role allows CW Logs                     | Function logging perms stripped       | [ ]  |
| DynamoDB Streams       | Table `stream_enabled = true`                    | Table with streams off                | [ ]  |

### Tier 2 — Build SECOND (cheap, more wiring)

| Log Source | "Logging ON" = | Done |
|---|---|---|
| GuardDuty | Detector enabled | [ ] |
| Security Hub | Hub enabled | [ ] |
| Detective | Graph enabled | [ ] |
| Inspector2 | Enabler resource active | [ ] |
| Macie2 | Account enabled | [ ] |
| WAF Logs | Web ACL + logging config → destination | [ ] |
| Route53 Resolver Query Logs | Resolver query log config + VPC association | [ ] |
| API Gateway Access Logs | Stage `access_log_settings` set | [ ] |

### Tier 3 — Build LAST, gate behind `enable_expensive` ($$ / hour)

> Only stand these up when actively testing the row. **Destroy immediately after.**

| Log Source | "Logging ON" = | Cost note | Done |
|---|---|---|---|
| Network Firewall Logs | Firewall + logging config → S3/CW | Firewall endpoint pricey/hour | [ ] |
| OpenSearch Logs | Domain log publishing enabled | Domain ~$/hour | [ ] |
| RDS Export Logs | Instance `enabled_cloudwatch_logs_exports` | Instance ~$/hour | [ ] |
| EKS Audit Logs | Cluster with `audit` in enabled log types | Cluster $0.10/hr + nodes | [ ] |

### Phase 1 Decisions (lock before coding)

- [ ] **Log destination:** S3-centric (recommended for IR collection) vs mixed S3 + CloudWatch
- [ ] **First build scope:** Tier 1 only (recommended) vs all tiers at once
- [ ] **Traffic instance:** include a `t3.micro` in the VPC for Phase 2 generation? (recommended yes)

---

## Phase 2 — Data Generation (driver script)

One script (bash/Python) that maps 1:1 to Phase 1 and forces real log content.

| Service | Generation action | Done |
|---|---|---|
| CloudTrail | Run a batch of AWS API calls (apply itself also generates) | [ ] |
| VPC Flow | Instance curls/pings outbound | [ ] |
| ALB | `curl` the ALB DNS in a loop | [ ] |
| S3 access | PUT/GET objects repeatedly | [ ] |
| CloudFront | Hit the distribution URL | [ ] |
| API Gateway | Call the endpoint | [ ] |
| Lambda | `aws lambda invoke` | [ ] |
| Route53 Resolver | DNS queries from the instance | [ ] |
| WAF / Network Firewall | Send matching + blocked traffic | [ ] |
| DynamoDB Streams | Put/update/delete items | [ ] |
| GuardDuty | `create-sample-findings` (instant) + a Stratus detonation for realism | [ ] |
| AWS Config | Toggle a resource attribute to force a change record | [ ] |
| EKS audit | A few `kubectl` calls | [ ] |
| Inspector2 / Macie2 / SecurityHub / Detective | Enabled = self-generate; seed/sample where supported | [ ] |

### Realistic activity via Stratus Red Team

```bash
export AWS_REGION=us-east-1
stratus detonate aws.persistence.iam-create-admin-user
# generates CreateUser / AttachPolicy CloudTrail events
# may trigger GuardDuty findings
```

### ⚠️ Log delivery delays (build a wait/poll step)

- CloudTrail → ~5–15 min to S3
- VPC Flow / ELB / S3 access → ~5 min to hours
- GuardDuty findings → minutes (sample) to hours (real)

Don't let the tool report "no logs" just because they haven't flushed yet.

---

## Validation Loop

```bash
terraform plan                          # always review first
infracost breakdown --path .            # know cost before applying

terraform apply -var="enable_logging=true"
# → run tool → confirm FULL coverage (no false positives)

terraform apply -var="enable_logging=false"
# → run tool → confirm it CATCHES every gap

terraform destroy                       # tear it ALL down
```

### Results Matrix (fill in per run)

| Log Source | Expected (on/off) | Detected | Pass/Fail | Notes |
|---|---|---|---|---|
| CloudTrail | | | | |
| AWS Config | | | | |
| VPC Flow Logs | | | | |
| ELB/ALB | | | | |
| Route53 Resolver | | | | |
| Network Firewall | | | | |
| S3 Access | | | | |
| CloudFront | | | | |
| API Gateway | | | | |
| Lambda | | | | |
| OpenSearch | | | | |
| RDS Export | | | | |
| DynamoDB Streams | | | | |
| GuardDuty | | | | |
| Security Hub | | | | |
| Detective | | | | |
| Inspector2 | | | | |
| Macie2 | | | | |
| WAF | | | | |
| EKS Audit | | | | |

---

## Cost Control Checklist

- [ ] Everything in **one region**
- [ ] Every resource tagged `Project=logging-test`
- [ ] Tier 3 (EKS, OpenSearch, RDS, Network Firewall, NAT GW) only up when actively testing
- [ ] `infracost` run before each apply
- [ ] Budget alert active
- [ ] **`terraform destroy` after every session** — verify EKS/OpenSearch/RDS/NAT are gone in console

---

## Phase 5 — Always Tear Down

- [ ] `terraform destroy`
- [ ] Confirm in console: EKS, OpenSearch, RDS, NAT Gateway actually deleted (bill killers)

---

## Open Questions / Notes

- Confirm: does the tool check **config state** only, or also **parse log content**?
  (We're doing content generation, so both will be exercised.)
- Decide S3-centric vs mixed destinations.
- Decide first-build scope (Tier 1 recommended).

---

## Next Action

➡️ **Lock the 3 Phase 1 decisions**, then write **Tier 1 Terraform** with the `enable_logging` toggle.
