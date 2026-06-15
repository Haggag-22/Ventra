# Releasing & versioning Ventra

PyPI holds **only clean, tagged releases** (`0.1.0`, `0.1.1`, `1.0.0`). Day-to-day testing pulls
your latest code straight from **git** — so the public PyPI page stays tidy while you can still
fetch any push with one command.

| Who | Runs | Gets |
|-----|------|------|
| **You** | the repo | `ventra gui` (hot reload) + run the collector locally or from git in CloudShell |
| **Client** | `ventra` in CloudShell | the latest **tagged** release from PyPI |
| **Analyst (v1+)** | a packaged desktop app | the console GUI (not built here yet) |

## How versioning works

The version comes from git — there's no version string to hand-edit.

- **Tag `vX.Y.Z`** → builds exactly `X.Y.Z`. This is what gets published to PyPI.
- **A working tree / git install between tags** → a dev version like `0.1.2.dev4+g1a2b3c4`. The
  `+g<hash>` is the exact commit, so you always know what you're testing — and it lands in the
  evidence package's `manifest.tool_version`.

Dev versions never go to PyPI; only tags do.

## Your day-to-day loop

1. **Edit code.** `ventra gui` shows the console with hot reload.
2. **Test the collector** — easiest is locally against your AWS test account (boto3 uses your
   local creds, same as CloudShell uses its role); editable install runs your working tree, so
   no push needed:
   ```bash
   aws sso login                  # or a profile
   ventra collect aws --case TEST-001 --out ~/ventra-evidence --no-ingest
   ```
3. **Push** whenever you like — pushing to `main` does **not** publish anything.

## Testing your latest push in CloudShell

CloudShell has `pip` but not `pipx`, so use the installer script — it sets up a private venv
with pip (no pipx needed), installs ventra from your `main` branch, and puts `ventra` on PATH.
Run the **same line** the first time and after every push; with the git spec it force-reinstalls
the latest code:

```bash
VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git@main' \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh)"

ventra collect aws --case TEST-001 --out ~/ventra-evidence
```

> Prefer pipx? Install it once with `python3 -m pip install --user pipx && python3 -m pipx
> ensurepath` (reopen the shell), then `pipx install "ventra @ git+https://github.com/Haggag-22/Ventra.git@main"`
> and `pipx reinstall ventra` after each push.

## Cutting a release (what clients get)

When something is ready for clients, tag it:

```bash
git tag v1.0.0
git push origin v1.0.0
```

That publishes `1.0.0` to PyPI and creates a GitHub Release. Then a client gets it with the
`install-cloudshell.sh` one-liner (it `pip install`s the latest release from PyPI — no pipx
needed). Workflow: [`.github/workflows/publish.yml`](.github/workflows/publish.yml).

## First-time setup (once)

- PyPI: configure the trusted publisher (owner `Haggag-22`, repo `Ventra`, workflow
  `publish.yml`, environment left blank / "(any)"). Already done.
- Push a baseline tag so dev versions read `0.1.2.devN` rather than `0.0.0.devN`:
  `git tag v0.1.1 && git push origin v0.1.1` (matches the `0.1.1` already on PyPI; the publish
  step skips it via `skip-existing`).
- Tidy up any stray `0.0.0.post*` dev builds on PyPI (Options → delete on that row) — those came
  from the brief continuous-publish experiment and aren't real releases.

## The console GUI

No Docker. Today the console runs from a clone with `ventra gui` (hot reload). The **v1
distribution will be a packaged desktop app** that analysts install; the collector keeps
shipping via PyPI / CloudShell (a desktop app can't run inside a client's cloud shell).
