"""GCP collectors — scaffolded for a later phase.

GCP reuses the Evidence Package Format and the console unchanged. Planned baseline sources
mirror the AWS Tier 1 set:

  * cloud_audit_admin   — Cloud Audit Logs: Admin Activity (~ CloudTrail management events)
  * cloud_audit_data    — Cloud Audit Logs: Data Access
  * vpc_flow            — VPC Flow Logs
  * scc_findings        — Security Command Center findings (~ GuardDuty / Security Hub)
  * iam_policy          — IAM policy bindings & service accounts (~ IAM)
  * login_events        — Workspace / Cloud Identity login events (~ console logins)

Implement each as a Collector subclass under this package and register it in a
``GCP_REGISTRY``, exactly as the AWS package does.
"""

# Intentionally empty until Phase 7. See docs/ROADMAP.md.
