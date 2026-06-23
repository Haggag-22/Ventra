## Deployment profile: EC2 collector instance

Recommended when CloudShell limits apply or the client prefers a **dedicated EC2 instance** with an instance profile.

1. Launch (or use) a private EC2 instance in the client account with **no inbound** access (SSM Session Manager only).
2. Attach an instance profile containing the narrowed policy from `iam/`.
3. Copy the kit to the instance (S3, SSM, or secure SCP).
4. Run the bootstrap helper, then collect:

```bash
unzip ventra-kit-*.zip -d ventra-kit && cd ventra-kit
chmod +x ec2-bootstrap.sh run.sh ventra.py
./ec2-bootstrap.sh
./run.sh --out /opt/ventra-evidence
```

5. Copy the sealed package from `/opt/ventra-evidence/` to your evidence bucket or secure transfer path.
6. Terminate or snapshot the instance per client retention policy.

See `ec2-bootstrap.sh` for a minimal Python venv + dependency install using the bundled wheel when present.

### Tradeoffs (read before you run)

| | EC2 / VM |
|---|----------|
| **Best for** | Large S3-resident logs, long runs, caps removed or raised, unattended collection |
| **Avoid when** | Client cannot provision a VM or wants zero infrastructure |

**Capacity & time**

- Disk and runtime scale with **instance type and volume size** — attach enough EBS for the sealed package plus temp staging (often tens to hundreds of GB for big flow/log pulls).
- Sessions via SSM can stay up for **hours**; no Cloud Shell ~20 min idle limit.
- Still respects `max_records_per_source` in `acquisition.yaml` if manually set — omit it for maximum API completeness.

**Data completeness**

- **Most complete** profile in this kit: best chance to pull **all records** within configured caps for API and S3-backed sources.
- Does not bypass Ventra’s per-source caps or client-side S3 listing limits — check manifest gaps after ingest.

**Operational cost**

- Requires launching/managing an instance, instance profile, and secure copy-out of the evidence package.
- Client must approve VM cost and cleanup (terminate or snapshot per policy).

**When to switch profile:** Use **Cloud Shell** for quick proof-of-access; use **Workstation** when EC2 provisioning is not allowed.
