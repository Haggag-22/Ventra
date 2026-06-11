# Changelog

All notable changes to Harbor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Docker Compose stack for the analyst workstation; Terraform reference forensics
  environment.

[Unreleased]: https://example.com/harbor/compare/main...HEAD
