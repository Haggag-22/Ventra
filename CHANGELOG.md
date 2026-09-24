# Changelog

All notable changes to Ventra are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (packaging)
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

### Added
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

[Unreleased]: https://github.com/Haggag-22/Ventra/commits/main
