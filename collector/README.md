# Harbor Collector

Read-only cloud forensic triage collector. Runs in the client's cloud shell, pulls exactly
the logs and artifacts IR needs, and seals them into a signed
[evidence package](../docs/evidence-package-format.md).

**AWS is the first supported cloud.** Azure and GCP are scaffolded for later phases.

## Install

```bash
pip install harbor-collector            # add [zstd] for zstandard compression
```

## Run

```bash
harbor-collect aws --profile baseline --case CASE-2026-0042 --since 2026-05-11 \
  --regions us-east-1,us-west-2 --out ./harbor-evidence
```

See the [Operator Runbook](../docs/runbooks/operator.md) for the full walkthrough, profiles,
CloudShell limits, and transport options.

## Design rules

- **Read-only.** Zero mutating API calls. The `readonly-guard` CI check enforces this; the
  required IAM policy is published at [`docs/iam-policies/`](../docs/iam-policies/).
- **Hash on acquisition.** Every source is SHA-256'd before it leaves the account.
- **Pure collectors.** Each module takes a context (boto3 session, regions, window) and
  returns a `SourceResult`. Easy to test with `moto`.
- **Gaps are evidence.** A disabled/empty source is recorded in the manifest, not hidden.

## Module map

```
harbor_collector/
  cli.py                      argument parsing, entry point
  common/
    models.py                 SourceResult, CollectionContext, Manifest dataclasses
    base.py                   Collector base class + registry
    chain_of_custody/         hashing, manifest assembly, signing
    packaging/                tar + zstd sealing
    transport/                local / s3-presigned / sftp
    profiles/                 *.yml preset bundles
  aws/
    runner/                   orchestrates the run for AWS
    control_plane/            cloudtrail, config
    network/                  vpc_flow, waf, ...
    identity/                 iam, sts, account
    detections/              guardduty, securityhub, macie, detective
    workloads/                ec2, ...
  tools/verify_readonly.py    static check that a policy/module is read-only
```
