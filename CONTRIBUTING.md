# Contributing to Ventra

Thanks for helping. Ventra runs inside client cloud accounts during incidents, so the bar is
"forensically sound first, convenient second." Keep PRs focused and small.

## Ground rules (non-negotiable)

- **The collector is read-only.** No mutating cloud API calls, ever. The `readonly-guard` check
  (`python -m collector.tools.verify_readonly`) enforces this in CI.
- **Integrity guarantees don't regress.** Changes to packaging, hashing, manifests, or
  verification need a second maintainer's review.
- **No telemetry, no outbound calls from the console.**
- **No real customer data or credentials in the repo.** Fixtures are synthetic. Never commit
  `.kit` files or evidence packages — kits can embed short-lived cloud credentials.

## Dev setup

You need [uv](https://docs.astral.sh/uv/) and git. Node.js is only needed for console UI work.

```bash
git clone https://github.com/Haggag-22/Ventra.git
cd Ventra
uv sync                 # .venv with the locked deps + dev tools, all packages editable
uv run ventra --help
```

Pip-style alternative: `uv venv && uv pip install -e ".[dev]"`.

> **macOS / iCloud:** don't keep the clone in an iCloud-synced folder (Desktop/Documents with
> "Desktop & Documents Folders" on). iCloud creates `name 2.py` conflict copies — which end up in
> builds and even inside `.git/` — and marks files in `.venv` hidden, which makes Python skip the
> editable-install `.pth` files so `import collector` fails outside pytest. `make install` clears
> the hidden flag, but moving the clone (e.g. to `~/src/Ventra`) avoids both problems.

## Before you push

```bash
uv run pytest                              # full suite (tests/)
uv run ruff check                          # lint
uv run ruff format                         # format (CI runs `ruff format --check`)
uv run python -m collector.tools.verify_readonly --collectors
uv run ventra artifacts validate --strict  # artifact YAML catalog
```

These are exactly what `.github/workflows/ci.yml` runs on every pull request, plus a build of the
sdist/wheel and a fresh `uvx`/`uv tool install` smoke test of the built wheel.

## Repository layout (for packaging)

One distribution, `ventra`, ships three import packages:

| Package | Source | Role |
|---------|--------|------|
| `collector` | `collector/` | the `ventra` CLI, collectors, kits, evidence packaging |
| `ventra_ingester` | `ingester/ventra_ingester/` | verify / normalize / load (`ventra-ingest`, `ventra-verify`, `ventra-export`) |
| `app` | `console/backend/app/` | console API (`ventra gui`, `ventra-console`) |

The build backend is [hatchling](https://hatch.pypa.io/). `hatch_build.py` copies `artifacts/`,
`schemas/`, `docs/iam-policies/`, and — when built — the static console
(`console/frontend/out/`, via `scripts/build-console-static.sh`) into `collector/_*` inside the
wheel; `collector/paths.py` finds them at runtime and falls back to the repo copies in a checkout.
The version comes from the latest git tag (`hatch-vcs`); there is no version string to edit.

`ingester/` and `console/backend/` keep their own `pyproject.toml` because `ventra gui` in a
source checkout installs them editable; their code ships inside the single `ventra` wheel.

Dependencies: the base install carries every cloud SDK so any `ventra collect <cloud>` works
after `uvx ventra`. The `aws`/`azure`/`gcp`/`kubernetes` extras mirror those lists — keep the
two in sync when adding a cloud dependency. Optional features get their own extra (`sftp`,
`enrich`).

## Known pre-existing issues

The packaging/tooling pass deliberately left collection and verification logic untouched. Lint
findings that point at real logic questions are pinned to their files under
`[tool.ruff.lint.per-file-ignores]` in `pyproject.toml` rather than silenced repo-wide — fix them
in their own PRs and delete the ignore entry. Deferred behaviour-neutral rewrites (`UP017`,
`UP035`, `SIM1xx`, …) are listed in `[tool.ruff.lint] ignore` for the same reason.
`tests/console/test_store.py::test_vpc_flow_collection` is marked `xfail(strict=True)` for a
known store/demo-generator mismatch; CI will fail once it passes, so remove the marker then.

## Releasing

Maintainers tag a commit (`git tag vX.Y.Z && git push origin vX.Y.Z`); `.github/workflows/publish.yml`
builds, checks, and publishes to PyPI with Trusted Publishing (OIDC — no stored tokens), then
creates a GitHub Release. Details in [`RELEASING.md`](RELEASING.md).

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Report security issues
privately — see [SECURITY.md](SECURITY.md).
