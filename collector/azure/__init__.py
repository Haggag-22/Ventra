"""Azure collectors — scaffolded for a later phase.

Azure reuses the Evidence Package Format and the console unchanged; only the acquisition
layer here is Azure-specific. Planned baseline sources mirror the AWS Tier 1 set:

  * activity_log      — Azure Activity Log (control-plane, ~ CloudTrail)
  * entra_signin      — Microsoft Entra ID sign-in logs (~ console logins / STS)
  * entra_audit       — Entra ID audit logs (directory changes)
  * nsg_flow          — NSG flow logs (~ VPC Flow Logs)
  * defender          — Microsoft Defender for Cloud alerts (~ GuardDuty)
  * rbac              — role assignments & definitions (~ IAM)

Implement each as a Collector subclass under this package and register it in an
``AZURE_REGISTRY``, exactly as the AWS package does.
"""

# Intentionally empty until Phase 6. See docs/ROADMAP.md.
