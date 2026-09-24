# Security policy

Ventra is used during incident response against production cloud accounts, so security reports
get priority over everything else.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
[**Report a vulnerability**](https://github.com/Haggag-22/Ventra/security/advisories/new)
(Security → Advisories → *Report a vulnerability*).

Include what you can of:

- the affected component (collector, ingester, console backend/frontend, kit builder, installer
  scripts) and version (`ventra --version`);
- steps to reproduce, and the impact you see;
- any logs — **scrubbed** of account IDs, ARNs, tenant/subscription/project IDs, IPs, tokens,
  and customer data.

You should get an acknowledgement within a few days. Fixes ship as a new tagged release on PyPI;
the advisory is published once a fixed version is available.

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/ventra/) receives security fixes.
Upgrade with `uv tool upgrade ventra` (or `pipx upgrade ventra`).

## What we consider in scope

- **Read-only invariant:** any path by which the collector could call a mutating cloud API, or by
  which a shipped IAM policy grants a mutating action.
- **Evidence integrity:** ways to alter a sealed package, its manifest, or its hashes without
  `ventra-verify` / ingest detecting it.
- **Credential handling:** leakage of cloud credentials into packages, manifests, logs, or the
  console; weaknesses in how Collection Kits embed short-lived credentials.
- **Console:** authentication/RBAC bypass, path traversal in case or upload handling, and any
  outbound network call or telemetry (the console is designed to make none).
- **Supply chain:** the build/release pipeline, installer scripts in `bin/`, and dependencies
  pinned in `uv.lock`.

## Handling Collection Kits and evidence

`.kit` files built with embedded connection auth contain short-lived cloud credentials
(`credentials/*.json`). Treat kits and evidence packages as secrets: never commit them, attach
them to issues, or share them outside the engagement. The repository's `.gitignore` blocks
`*.kit` and local evidence directories for this reason.
