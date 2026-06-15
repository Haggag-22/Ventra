# ===========================================================================
# Automatic detection of already-enabled singleton services.
#
# GuardDuty / Security Hub / Macie / Detective / Inspector2 allow only ONE per
# account/region, so creating one that already exists fails. We probe the
# account (read-only) at plan time and only manage the services that are NOT
# already on — no manual flags required.
#
# The probe result is snapshotted into a null_resource on first apply and then
# pinned (ignore_changes). That stops the toggle from flip-flopping once
# Terraform itself enables a service (otherwise the next plan would see it "on"
# and try to destroy it).
# ===========================================================================

data "external" "detection" {
  program = ["bash", "${path.module}/scripts/detect_services.sh"]
  query   = { region = var.region }
}

resource "null_resource" "detection_snapshot" {
  triggers = {
    guardduty   = data.external.detection.result.guardduty
    securityhub = data.external.detection.result.securityhub
    macie       = data.external.detection.result.macie
    detective   = data.external.detection.result.detective
    inspector2  = data.external.detection.result.inspector2
  }

  # Pin the first observed state; ignore later drift so managed services stay managed.
  lifecycle {
    ignore_changes = [triggers]
  }
}

# Config recorder is also a per-region singleton (max 1). Kept in a SEPARATE
# snapshot so adding it never disturbs (replaces) the detection snapshot above.
resource "null_resource" "config_snapshot" {
  triggers = {
    config = data.external.detection.result.config
  }
  lifecycle {
    ignore_changes = [triggers]
  }
}

locals {
  # "Pre-existing" = enabled in the account before this harness managed it.
  pre = null_resource.detection_snapshot.triggers

  # Manage a service only when logging is on AND it wasn't already enabled.
  do_guardduty   = var.enable_logging && local.pre.guardduty != "enabled"
  do_securityhub = var.enable_logging && local.pre.securityhub != "enabled"
  do_detective   = var.enable_logging && local.pre.detective != "enabled"
  do_inspector2  = var.enable_logging && local.pre.inspector2 != "enabled"
  do_macie       = var.enable_logging && local.pre.macie != "enabled"

  do_config = var.enable_logging && null_resource.config_snapshot.triggers.config != "enabled"
}
