# Security Policy

Harbor is used in adversarial settings. Vulnerability reports get a clean, private path.

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Email the maintainers at `security@harbor-ir.example` (replace before public release) with:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept
- Affected component (`collector`, `ingester`, `console`) and version

You will receive an acknowledgement within 3 business days and a remediation timeline
after triage. We support coordinated disclosure and will credit reporters who wish it.

## Scope of particular concern

Because Harbor handles evidence, we treat the following as high severity:

- Any path that lets the **collector mutate client state** (it must be strictly read-only).
- Any flaw that **breaks integrity guarantees** — hash bypass, manifest forgery, signature
  validation that can be skipped.
- **Evidence tampering** in the ingester or console, or breaking the immutability of a
  sealed package.
- **Outbound data exfiltration** from the console (it must make no external calls by
  default) — including unexpected network requests, telemetry, or font/CDN fetches.
- Privilege escalation across the console's RBAC roles.

## Release signing

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign). The public
key lives at `docs/keys/harbor-release.pub`. Verify before running anything a client will
paste into their environment:

```bash
cosign verify-blob --key docs/keys/harbor-release.pub --signature harbor-collector.whl.sig harbor-collector.whl
```

## Supported versions

During pre-1.0 development only the latest minor release receives security fixes.
