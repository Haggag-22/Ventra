## Deployment profile: Cloud Shell

Recommended when the client runs collection inside **{{CLOUD}} Cloud Shell** (or Cloud Shell equivalent) with a read-only role attached.

1. Attach the narrowed policy from `iam/` to the operator role (security team review first).
2. Upload this kit zip to the cloud shell, or clone from your secure file share.
3. Unzip and run:

```bash
unzip ventra-kit-*.zip -d ventra-kit && cd ventra-kit
chmod +x run.sh ventra.py
./run.sh --out ~/ventra-evidence
```

4. Download the sealed `.tar.zst` from the shell environment.
5. Send the package to your IR team for ingest into Ventra Investigate.

### Tradeoffs (read before you run)

| | Cloud Shell |
|---|-------------|
| **Best for** | Quick scoped pulls, proof-of-access, small/medium log volume |
| **Avoid when** | You need every record from large S3-resident logs, or runs longer than ~20 minutes |

**Capacity & time**

- Home directory is typically **~1 GB**. The sealed evidence package and temp files must fit there — large multi-source pulls can fail with “disk full” even when IAM is correct.
- Sessions **idle out** after roughly **20 minutes** without activity. Long collections may stop mid-run; there is no built-in resume.
- If `max_records_per_source` is manually set in `acquisition.yaml`, Ventra **stops at that cap per source** — you will **not** get all records. For a full pull, use an EC2/VM profile and omit that field from the yaml.

**Data completeness**

- Cloud Shell is fine for API-backed sources (CloudTrail API, GuardDuty, etc.) within caps and time limits.
- **S3-heavy sources** (VPC Flow from buckets, CloudTrail archives, large access-log prefixes) may be **truncated or skipped** when local staging space or session time runs out. Treat Cloud Shell output as **best-effort scoped collection**, not a forensic mirror of every object in the account.

**Other**

- No extra VM to provision — fastest path for the client.
- Credentials come from the signed-in Cloud Shell user; no local install required.

**When to switch profile:** Rebuild the kit with **Workstation** (responder jump host) or **EC2 / VM** (dedicated instance, more disk, longer runs) if gaps in the manifest or missing S3-resident logs are unacceptable.
