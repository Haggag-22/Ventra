# Security Command Center is organization-scoped and usually enabled by an org admin. This
# optional Pub/Sub topic models an SCC findings export. The scc_findings collector reads
# findings at the organization level, so it needs org-level access regardless of this topic.
#
# Targets: scc_findings (org-level; needs org_id + Organization Admin)

resource "google_pubsub_topic" "scc" {
  count   = var.enable_scc && var.org_id != "" ? 1 : 0
  name    = "${local.name}scc"
  project = var.project_id

  depends_on = [null_resource.apis_ready]
}
