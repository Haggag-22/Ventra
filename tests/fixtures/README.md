# Test fixtures

**Synthetic data only. Never commit real customer evidence.**

## Demo case generator

[`generate_demo_case.py`](generate_demo_case.py) builds a realistic, fully synthetic Harbor
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

## Sanitization policy

Any fixture derived from real telemetry must be scrubbed: replace account IDs, ARNs, IPs,
hostnames, and any PII with documented placeholders (`123456789012`, `203.0.113.x`,
`example.com`). When in doubt, generate synthetic data instead — the generator above is the
preferred source of test data.
