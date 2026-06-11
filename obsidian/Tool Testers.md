

## 1. Attack-simulation tools (generate CloudTrail events + real GuardDuty findings)

|Tool|Maintainer|Why use it|
|---|---|---|
|**Stratus Red Team**|Datadog (`DataDog/stratus-red-team`)|**Best pick.** Self-contained Go binary, ~35 AWS techniques mapped to MITRE ATT&CK, clean `warmup → detonate → cleanup`. Many techniques deliberately **trigger GuardDuty** — so CloudTrail _and_ GuardDuty get real data.|
|**Pacu**|Rhino Security Labs (`RhinoSecurityLabs/pacu`)|Modular AWS exploitation framework — IAM priv-esc, enumeration, persistence, exfil. Generates rich, realistic CloudTrail/STS trails.|
|**Leonidas**|WithSecure (`WithSecureLabs/leonidas`)|YAML-defined AWS attacks + companion CloudFormation environment. Broad API-level coverage.|
|**Atomic Red Team**|Red Canary (`redcanaryco/atomic-red-team`)|Has an AWS/cloud section (ATT&CK T-codes). Lighter than Stratus but familiar.|
## 2. Infrastructure deployers (stand up resources + misconfigs to inventory)

|Tool|Maintainer|What it gives you|
|---|---|---|
|**sadcloud**|NCC Group (`nccgroup/sadcloud`)|Terraform that deploys deliberately insecure AWS — public S3, open SGs, unencrypted KMS/secrets. **Perfect for your S3/Config/Security Hub collectors.**|
|**CloudGoat**|Rhino Security Labs (`RhinoSecurityLabs/cloudgoat`)|Terraform vulnerable scenarios + the attack path to exploit them. Covers infra **and** activity.|
|**TerraGoat**|Prisma Cloud (`bridgecrewio/terragoat`)|Vulnerable Terraform across many services — good general inventory.|
|**AWSGoat**|INE Labs (`ine-labs/AWSGoat`)|Vulnerable app with a real exploitation chain.|

## 3. The shortcut for detection collectors (fastest data, no attacking)

- **GuardDuty:** `aws guardduty create-sample-findings --detector-id <id>` → instantly populates every finding type.
- **Security Hub:** enable it + CIS/Foundational standards → findings appear from your sadcloud misconfigs within ~1 hour.
- **Macie:** enable it, drop fake-PII files (e.g. test card number `4111 1111 1111 1111`) in a bucket, run a classification job → real findings.
- **Detective:** slowest/priciest — needs GuardDuty running ~48h first. Consider testing its "not enabled" gap path instead unless you need it.

## ⚠️ Before you run anything

1. **Dedicated throwaway account only** — never production or shared.
2. **Set an AWS Budget alarm (~$20) first.** Big costs: GuardDuty, Security Hub, Macie, **Detective** (priciest), Config, and **NAT gateways** for flow logs. Enable → test → **disable**.
3. **Always run the cleanup/`terraform destroy`** step — orphaned resources cost money.

## Recommended sequence for _your_ tool

1. **`terraform apply` sadcloud + a small VPC with flow logs → CloudWatch** — lights up ~8 collectors (S3, IAM, KMS, Secrets, EC2, SGs, flow logs) with realistic misconfigs.
2. **Enable GuardDuty + Security Hub + Config + Macie**, run `create-sample-findings` and a Macie job — lights up the 4 detection collectors.
3. **Run Stratus Red Team** — detonate `aws.exfiltration.ec2-share-ebs-snapshot`, `aws.persistence.iam-create-admin-user`, `aws.defense-evasion.cloudtrail-stop`. This generates CloudTrail/STS activity **and** real GuardDuty findings.
4. **`harbor-collect aws --case CASE-LIVE-0001`** over that window → send me the `manifest.json` and we compare collected-vs-expected together.

The Stratus **`ec2-share-ebs-snapshot`** technique is your single highest-value test — it exercises exactly the shared-snapshot detection I rebuilt today with `DescribeSnapshotAttribute`.
