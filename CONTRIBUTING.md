# Contributing to Harbor

Thanks for helping build forensically-sound cloud IR tooling. This guide covers the
ground rules that keep Harbor trustworthy.

## Non-negotiables

These are not style preferences — they are correctness requirements for an evidence tool:

1. **The collector is read-only.** A PR that adds any mutating AWS/Azure/GCP API call to the
   collector will be rejected. The CI `readonly-guard` check scans for disallowed verbs
   (`Create*`, `Put*`, `Delete*`, `Update*`, `Modify*`, `Terminate*`, `Run*`, `Start*`,
   `Stop*`, `Attach*`, `Associate*`, etc.). If you believe an exception is warranted, open
   an issue first.
2. **Never weaken integrity.** Hashing on acquisition, manifest signing, and ingest-time
   verification are load-bearing. Changes here require a second maintainer review.
3. **No telemetry, no outbound calls** in the console by default. No CDN fonts, no analytics,
   no map tiles fetched at runtime. Ship assets locally.
4. **Fixtures only.** Never commit real customer data. All test data must be synthetic or
   thoroughly sanitized — see `tests/fixtures/README.md`.

## Project layout

- `collector/` — Python, `boto3`. Cloud providers (`aws/`, `azure/`, `gcp/`) each hold
  their collector modules. Shared code lives in `lib/`. Every registered collector runs
  on each invocation — no profiles or presets.
- `bin/` — CloudShell bootstrap scripts (not part of the pip package).
- `ingester/` — Python. `parsers/` (source-specific) → `normalizer/` (unified schema) →
  `loaders/`. Parsers must be pure and independently versioned.
- `console/backend/` — FastAPI over the case store. Thin; all RBAC enforced server-side.
- `console/frontend/` — Next.js + Tailwind + shadcn-style components. One module per panel.

## Development setup

```bash
# Python tooling (collector + ingester + backend)
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" -e "ingester[dev]" -e "console/backend[dev]"
pre-commit install

# Frontend
cd console/frontend && npm install && npm run dev
```

## Standards

- **Python**: `ruff` (lint + format), `mypy` (typed), `pytest`. Target 3.11+.
- **TypeScript**: `eslint`, `prettier`, strict mode. No `any` without justification.
- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, `parser:` …).
- **Tests**: every parser ships with a fixture + a round-trip test. Every collector ships
  with a mocked-boto3 test. The console ships with an e2e against the demo case.

## Adding a new collector

1. Add a module under `collector/aws/<group>/`.
2. Register it in `collector/aws/registry.py` (it will run automatically on every collection).
3. Add a fixture and a `moto`-mocked test under `tests/collector/`.
4. Document the artifact in `docs/evidence-package-format.md` and the IAM actions it needs
   in `docs/iam-policies/`.

## Adding a new parser / source to the console

1. Add a parser under `ingester/harbor_ingester/parsers/`.
2. Map it to the unified schema in `normalizer/`.
3. Add a fixture + round-trip test.
4. If it introduces a new event category, update the console's category palette.

## Pull requests

Use the PR template. CI must be green: lint, type-check, unit, integration, e2e, schema
validation, secret-scan, and `readonly-guard`. Keep PRs focused.
