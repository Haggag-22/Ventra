# Test fixtures

**Synthetic data only. Never commit real customer evidence.**

## Demo case generator

[`generate_demo_case.py`](generate_demo_case.py) builds a realistic, fully synthetic Ventra
evidence package using the collector's own packaging code (manifest, hashing, signing,
sealing). It encodes one coherent attack scenario:

> A leaked access key for `dbadmin` is used from a foreign IP — console login, account
> enumeration, privilege escalation (AdministratorAccess), persistence (new user + key),
> defense evasion (CloudTrail `StopLogging`), cross-account EBS snapshot sharing, sensitive
> S3 reads, and network exfiltration — with GuardDuty findings throughout.

```bash
python tests/fixtures/generate_demo_case.py --out tests/fixtures/
```

This produces `case-CASE-2026-0042-...-.tar.zst`, used by:

- the ingester pipeline test (`tests/ingester/test_pipeline.py`),
- the console demo and e2e,
- manual exploration of the GUI.

## Azure demo case generator

[`generate_azure_demo_case.py`](generate_azure_demo_case.py) builds a synthetic Azure/M365
evidence package with `manifest.cloud = "azure"`. It encodes one coherent attack scenario:

> A finance admin's Entra session is hijacked from a foreign IP — OAuth consent to a malicious
> app, service-principal credential add, RBAC escalation, blob storage reads, mailbox access
> (Unified Audit Log), and VNet flow exfiltration — with Defender alerts throughout. Several
> log sources are deliberately missing (NSG flow, DNS, Key Vault, App Gateway) to show realistic
> collection gaps.

```bash
make demo-azure
make ingest-azure
ventra gui
```

Open case **`CASE-2026-AZ42`** in the console to explore Azure-specific panels (Activity Log,
Entra sign-in/audit, Defender, VNet flow, M365 UAL, etc.).

Or run the generator directly:

```bash
python tests/fixtures/generate_azure_demo_case.py --out tests/fixtures/
ventra-ingest tests/fixtures/case-CASE-2026-AZ42-*.tar.zst --case-store ./cases
```

Used by `tests/ingester/test_azure_pipeline.py`.

## Sanitization policy

Any fixture derived from real telemetry must be scrubbed: replace account IDs, ARNs, IPs,
hostnames, and any PII with documented placeholders (`123456789012`, `203.0.113.x`,
`example.com`). When in doubt, generate synthetic data instead — the generator above is the
preferred source of test data.
