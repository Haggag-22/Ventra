# Targets: scc_findings (optional — org-level SCC is usually pre-enabled by org admin)

resource "google_pubsub_topic" "scc" {
  count   = var.enable_scc && var.org_id != "" ? 1 : 0
  name    = "${local.name}-scc"
  project = var.project_id
}
