## Deployment profile: IR workstation

Recommended when a responder runs the kit on a **jump host or local machine** with cloud CLI credentials (AWS profile, `az login`, or GCP ADC).

1. Attach or assume the read-only role described in `iam/`.
2. Unzip the kit on the workstation (do not email credentials — only the kit zip).
3. Bootstrap and collect:

```bash
unzip ventra-kit-*.zip -d ventra-kit && cd ventra-kit
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# If dist/ventra-*.whl is present:
pip install dist/ventra-*.whl
# AWS example:
python3 ventra.py --profile ir-readonly --out ./ventra-evidence
```

4. Transfer the sealed `.tar.zst` to the analyst console via your secure evidence channel.
5. Analyst imports the package in Ventra **Cases → Import package**.

### Tradeoffs (read before you run)

| | Workstation |
|---|----------------------|
| **Best for** | Responders with CLI access, medium pulls, flexible time window |
| **Avoid when** | Client policy forbids credentials on local machines, or you need many hours of unattended collection |

**Capacity & time**

- Disk and runtime limits depend on **your machine**, not the cloud provider’s shell quota — usually better than Cloud Shell for moderate packages.
- Local machines can sleep, VPN-drop, or lose network; long unattended runs are less reliable than EC2.
- If `max_records_per_source` is manually set in `acquisition.yaml`, collection still **stops at that cap** — omit it if you need more complete API pulls.

**Data completeness**

- Can pull **more complete** API and S3-backed sources than Cloud Shell **if** you have enough local disk and a stable connection.
- Very large S3-resident logs may still exceed local disk or IR transfer limits; use **EC2 / VM** with a large volume and stream/copy from there.

**Security & custody**

- Cloud credentials live on the workstation for the duration of the run — follow client rules for jump hosts and credential storage.
- Ventra console never stores client cloud keys; evidence leaves only via your agreed transfer channel.

**Other**

- Requires Python 3.11+ and either network access for `pip` or the bundled wheel in `dist/`.
- Operator must configure the correct AWS profile, `az login`, or GCP Application Default Credentials.

**When to switch profile:** Use **EC2 / VM** for multi-hour or multi-TB pulls; use **Cloud Shell** when the client cannot install anything locally but can upload a zip to the console.
