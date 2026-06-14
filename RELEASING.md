# Releasing & versioning Ventra

The model is **continuous delivery**: every push to `main` publishes a new version of the
`ventra` collector to PyPI, so you (or a client) can always fetch the latest with a plain
`pipx install ventra` / `pipx upgrade ventra`. No tagging needed for day-to-day work.

| Who | Runs | Gets |
|-----|------|------|
| **You** | the repo | `ventra gui` (hot reload) + run the collector locally or in CloudShell |
| **Client / your AWS test account** | `ventra` in CloudShell | latest pushed version, via `pipx install`/`upgrade ventra` |
| **Analyst (v1+)** | a packaged desktop app | the console GUI (not built here yet) |

## How versioning works

The version comes from git — there's no version string to hand-edit.

- **Push to `main`** → `0.1.1.post1`, `0.1.1.post2`, … (one per commit). A *normal* version, so
  `pip`/`pipx` install and upgrade to it by default.
- **Tag `vX.Y.Z`** → a clean `X.Y.Z` plus a GitHub Release with notes. Optional — use it to mark
  a milestone (e.g. `v1.0.0`); it does not change the day-to-day flow.

Either way the version lands in every evidence package's `manifest.tool_version`, so a package
always shows exactly which build collected it.

## Your day-to-day loop

1. **Edit code.** `ventra gui` shows the console with hot reload.
2. **Test the collector.** Easiest is locally against your AWS test account (boto3 uses your
   local creds, same as CloudShell uses its role):
   ```bash
   aws sso login                  # or a profile
   ventra collect aws --case TEST-001 --out ~/ventra-evidence --no-ingest
   ```
   Editable install = your working-tree code runs immediately, no push needed.
3. **Push** when you want it available in CloudShell. CI publishes it to PyPI automatically.

## Testing in CloudShell

After a push, CI publishes within a minute or two. Then in CloudShell:

```bash
# first time in a fresh CloudShell:
pipx install ventra

# already have it (fetch your latest push):
pipx upgrade ventra

# then:
ventra collect aws --case TEST-001 --out ~/ventra-evidence
```

> CloudShell may not ship `pipx`. Once per environment: `python3 -m pip install --user pipx &&
> python3 -m pipx ensurepath`, then reopen the shell. (The `curl … install-cloudshell.sh | bash`
> one-liner also still works and self-upgrades from PyPI.)

## Cutting a milestone (optional)

When you want a clean version number and release notes (e.g. for v1):

```bash
git tag v1.0.0
git push origin v1.0.0
```

That publishes `1.0.0` to PyPI and creates a GitHub Release. Workflow:
[`.github/workflows/publish.yml`](.github/workflows/publish.yml).

## First-time setup (once)

- Push a baseline tag so versions read `0.1.1.postN` rather than `0.0.postN`:
  `git tag v0.1.1 && git push origin v0.1.1`.
- PyPI: configure the trusted publisher (owner `Haggag-22`, repo `Ventra`, workflow
  `publish.yml`, environment left blank / "(any)").

## The console GUI

No Docker. Today the console runs from a clone with `ventra gui` (hot reload). The **v1
distribution will be a packaged desktop app** that analysts install; the collector keeps
shipping via PyPI / CloudShell (a desktop app can't run inside a client's cloud shell).
