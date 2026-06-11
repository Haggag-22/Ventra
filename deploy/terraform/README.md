# Reference forensics environment (Terraform)

A **reference** implementation of the isolated analysis environment from AWS's
[Forensic investigation environment strategies](https://aws.amazon.com/blogs/security/forensic-investigation-environment-strategies-in-the-aws-cloud/).
This is not required to run Harbor — the console runs fine on a laptop — but if your firm
wants to do analysis inside a dedicated AWS account, this is a sound starting point.

It provisions, in a **dedicated forensics account**:

- An **isolated VPC** with **no internet gateway** — outbound to AWS services goes through
  VPC endpoints only, so a compromised artifact can't call home.
- A **gateway VPC endpoint for S3** so evidence can be pulled from an evidence bucket
  without internet egress.
- **VPC Flow Logs** on the forensics VPC itself (you log your own investigative activity).
- A **highly restrictive security group** (no inbound; egress limited to the S3 prefix list).
- An **evidence S3 bucket** with **Object Lock (compliance mode)**, versioning, public access
  fully blocked, and SSE-KMS — immutable storage for sealed packages.
- IAM roles modelling **separation of duties**: `responder`, `investigator`, `custodian`.

> Review and adapt before applying. Pin provider versions, set your account/region, and run
> `terraform plan` first. The defaults favor isolation over convenience.

```bash
cd deploy/terraform
terraform init
terraform plan -var 'region=us-east-1'
# terraform apply   # only after review
```

## What this deliberately does NOT do

- It does not set up cross-account evidence sharing automation — that belongs to your
  acquisition runbook.
- It does not open any inbound access. Use SSM Session Manager (auditable, no bastion) to
  reach an analysis instance if you add one.
