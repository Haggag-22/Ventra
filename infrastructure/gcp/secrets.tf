# Secret Manager secret + version. The lab VM reads it on a timer, producing AccessSecretVersion
# data-access audit logs.
#
# Targets: secret_manager

resource "google_secret_manager_secret" "lab" {
  count     = var.enable_secret_manager ? 1 : 0
  secret_id = "${local.name}secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "lab" {
  count       = var.enable_secret_manager ? 1 : 0
  secret      = google_secret_manager_secret.lab[0].id
  secret_data = "ventra lab demo secret value"
}

# Project-level secretAccessor is already granted in main.tf; this records access at the
# secret resource too, matching how a real workload would be scoped.
resource "google_secret_manager_secret_iam_member" "lab" {
  count     = var.enable_secret_manager ? 1 : 0
  secret_id = google_secret_manager_secret.lab[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.lab.email}"
}
