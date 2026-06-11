# Harbor Roadmap

Semantic versioning. Dates are targets, not commitments.

| Phase | Scope | Deliverable |
|-------|-------|-------------|
| **0 — Foundation** ✅ | EPF spec frozen, manifest + event schemas, signing flow, read-only IAM policy, repo scaffold, design tokens | `docs/evidence-package-format.md` + skeleton |
| **1 — AWS Tier 1 collector** | The 7 baseline collectors, packaging, CloudShell bootstrap | First end-to-end run against a real account |
| **2 — Ingester + Console MVP** | verify/parse/normalize/load; Cases, Overview, Timeline, CloudTrail, Search panels | First demo case |
| **3 — AWS Tier 2 + remaining panels** | Identity, Network, Resources, Findings panels; Tier 2 collectors | Feature-complete for AWS |
| **4 — Public alpha** | Docs site, signing, demo case, contributor guide, ATT&CK mapping | Open-source release |
| **5 — Reporting + IOC/Hunt** | Report builder, IOC management, hunt packs | v1.0 |
| **6 — Azure** | Azure collectors reusing EPF + console unchanged | Multi-cloud |
| **7 — GCP** | GCP collectors | Multi-cloud complete |
| **8 — Integrations** | OpenSearch backend, OCSF/STIX export, Jira/Slack | Enterprise polish |

## Design tenets that won't change

- The collector stays read-only.
- The EPF is the only contract between tiers; it evolves under semver.
- The console works fully offline with zero telemetry.
- New clouds reuse the unified schema; the console never learns provider-specific logic.
