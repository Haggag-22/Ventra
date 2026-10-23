# Changelog

All notable changes to Ventra are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-23

First stable release. Earlier 0.x builds were previews and have been withdrawn from PyPI and
GitHub; their notes are kept at the end of this file.

### Added
- Acquire can choose where the Azure Activity Log comes from: the Monitor API or the
  subscription's diagnostic storage archive. Kit IAM is narrowed to the chosen source.
- Acquire can choose the CloudTrail source for AWS kits (LookupEvents, a bucket, or a trail).
- `ventra run` delivers the sealed package to the handoff set in Acquire's Enterprise profile
  (your IR bucket or a presigned URL). Bucket uploads use the machine's own AWS credentials, not
  the kit's read-only ones; the local copy is kept, and a failed upload makes the run exit
  non-zero. A bad transport spec stops the run before it collects anything.

### Changed
- `ventra import` (and auto-ingest after `ventra collect`) writes to the console's case store
  (`$VENTRA_HOME/cases`, else the user data folder for installs, else `./cases` in a source
  checkout), so CLI imports show up in `ventra gui`. `--case-store` and `VENTRA_CASE_STORE`
  still win.
- The console frontend moved to Next.js 15.5 and React 19.
- The README and runbooks follow the console workflow: build a Collection Kit in Acquire, run it
  from the console or with `ventra run`, then import the package under Cases.
- CI typechecks, lints and builds the console, bundles it into the wheel, and smoke-tests the
  installed console in headless Chromium.

### Fixed
- The installed console (`pip`/`uv`/`pipx`) can open cases and runs again. Case and run pages read
  the static-export placeholder `_` instead of the real ID, so every case showed a load error.
  Links between pages no longer force full page reloads, and pages hydrate without a React
  mismatch.
- Load errors no longer tell installed users to run `make ingest`.
- The AWS permissions list the console offers for download includes the CloudWatch Logs
  actions again.
- Kits no longer suggest a `--stream-to` flag that doesn't exist.

### Removed
- The M365 Unified Audit Log collectors (`unified_audit`, `unified_audit_search`) and the
  Azure `log_analytics` collector.

### Security
- A package whose manifest carries a cryptographic signature that Ventra cannot verify is no
  longer shown as "Sealed · verified" (green). Without a public key it can't tell a real
  signature from junk, so such packages are amber, like SHA-256-stamped ones.
- The console's frontend dependencies have no known advisories (`npm audit`).

## Pre-1.0 previews (withdrawn)

### [0.7.3] - 2026-09-26

#### Security
- Importing an evidence package can no longer write outside the case directory: archive
  members with `..`, absolute paths or drive letters are refused before anything is written.
- A package's `case_id` can no longer point outside the case store (it was used as a
  directory that import deletes and recreates).
- Saved connections (cloud keys, service-account JSON, kubeconfigs) are stored owner-only
  (`0600` file, `0700` directory; older stores are tightened on start) and the API no longer
  returns secret values, only which ones are set (`stored_secrets`).
- The console refuses requests whose `Host` isn't `localhost`/`127.0.0.1`/`::1` (plus
  `VENTRA_ALLOWED_HOSTS`), so a web page can't reach it through DNS rebinding, and the dev
  server binds `127.0.0.1` instead of all interfaces. There is still no login: the console is a
  single-user tool on the analyst's own machine.

#### Fixed
- Kit runs stage evidence under `--out` instead of `/tmp` (a small tmpfs on many nodes) and
  stream the tar into the compressor, so collections no longer fail with `ENOSPC`.
- Non-systemd Kubernetes node logs (syslog / kubelet.log fallback) get their timestamp and
  program from the line instead of an empty time.
- Event time sorting orders by the parsed instant, not the timestamp text.

#### Added
- Click-to-sort column headers on every case dashboard table (server-side for event logs).

### Earlier changes (0.7.2 and before)

#### Changed (packaging)
- Build backend is now **hatchling** + **hatch-vcs** (version still comes from git tags, same
  version strings). `hatch_build.py` replaces the setuptools `build_py` hook and stages the
  artifact catalog, schemas, IAM policies, and static console into the wheel.
- The sdist is an explicit allow-list; it no longer ships every tracked file (which included
  local `.kit` files and run output).
- Wheels and sdists no longer ship iCloud/Finder conflict copies (`cli 2.py`,
  `k8s_container_logs 2.yaml`, …); the latter showed up as a duplicate catalog artifact.
- `ventra collect <cloud> --list-packs`, `ventra artifacts validate`, and `ventra artifacts diff`
  use the bundled catalog instead of `./artifacts`, so they work from any directory.
- Extras: `aws`, `azure`, `gcp`, `kubernetes`, `all` (mirroring the base install), plus `sftp`
  (paramiko) and `enrich` (geoip2); `dev` extra for pytest/ruff. Removed the unused
  `azure-mgmt-security` dependency.
- Added the `ventra-ingest-watch` console script to the `ventra` wheel.
- CI: pull-request workflow (ruff, pytest on 3.11–3.14, read-only guard, catalog validation,
  fresh-install smoke test); tag release workflow split into build → PyPI (OIDC) → GitHub Release.

#### Added
- Project foundation: README, license (Apache-2.0), security policy, contributing guide.
- **Evidence Package Format (EPF) v1** specification and JSON Schemas (manifest, package,
  unified event).
- **AWS collector** with Tier 1 baseline modules: account context, CloudTrail, VPC Flow
  Logs config, GuardDuty, WAF, IAM snapshot, STS activity.
- Read-only IAM policy for the AWS collector.
- Packaging pipeline: tar + zstd, per-source SHA-256, manifest, detached signature.
- **Ingester**: signature/hash verification, source parsers, normalizer to the unified
  event schema, DuckDB/Parquet loader.
- **Analyst console**: FastAPI backend + Next.js frontend with Cases, Overview, Timeline,
  CloudTrail Analyzer, Identity, Network, Resources, Findings, Search, Report, and Settings.
- Demo case fixtures and an end-to-end collect → ingest → render path.
- Terraform reference forensics environment for the analyst workstation.

[1.0.0]: https://github.com/Haggag-22/Ventra/releases/tag/v1.0.0
