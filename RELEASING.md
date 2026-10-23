# Releasing Ventra

Maintainer notes. PyPI holds only tagged releases; pushing to `main` publishes nothing.

## Versioning

The version comes from git (hatch-vcs) — there is no version string to edit.

- **Tag `vX.Y.Z`** → builds exactly `X.Y.Z`. Only tags are published.
- **Between tags** → a dev version like `0.7.4.dev4+g1a2b3c4`. The `+g<hash>` names the exact
  commit and lands in each evidence package's `manifest.tool_version`.

## Cutting a release

1. Make sure `main` is green in CI and move the `[Unreleased]` notes in
   [`CHANGELOG.md`](CHANGELOG.md) under the new version.
2. Optional dry run: **Actions → Release → Run workflow** (or `gh workflow run publish.yml`).
   It builds the console and wheel and runs every check, but publishes nothing.
3. Tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

[`publish.yml`](.github/workflows/publish.yml) then builds the static console into the wheel,
runs `uv build`, checks the built version equals the tag, runs `twine check` and a fresh-install
smoke test, publishes to PyPI via Trusted Publishing (OIDC — no stored tokens), and creates a
GitHub Release with generated notes and the built files attached.

Users get it with `uv tool upgrade ventra` / `pipx upgrade ventra`, or the installers in
[`bin/`](bin/).

## Testing unreleased code in CloudShell

```bash
VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git@main' \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh)"
```

[`bin/install.sh`](bin/install.sh) accepts the same `VENTRA_INSTALL_SPEC` on a workstation.

## PyPI setup

The trusted publisher is configured (owner `Haggag-22`, repo `Ventra`, workflow `publish.yml`,
environment "(any)"). Keep the workflow filename: the PyPI entry is bound to it.

## CI

[`ci.yml`](.github/workflows/ci.yml) runs on pull requests and `main`: `ruff check`,
`ruff format --check`, `pytest` on Python 3.11–3.14, the read-only guard, artifact catalog
validation, a `frontend` job (`tsc --noEmit`, `next lint`, static export), and a build of the
wheel with that console bundled. The wheel gets a fresh-install smoke test, then
`scripts/smoke-packaged-console.py` starts `ventra gui`, imports a demo case and loads a case page
in headless Chromium, failing if the page calls `/api/cases/_/…` instead of the real case ID.
