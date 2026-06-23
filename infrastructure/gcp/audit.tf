# Targets: cloud_audit_admin, cloud_audit_system, cloud_audit_data, login_events, iam_policy, project

resource "google_project_iam_audit_config" "lab" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }

  depends_on = [google_project_service.apis]
}

resource "google_logging_project_sink" "audit" {
  name        = "${local.name}-audit-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""

  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_service_account" "lab" {
  account_id   = "${local.name}-sa"
  display_name = "Ventra lab service account"
  depends_on   = [google_project_service.apis]
}

resource "google_project_iam_member" "lab_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.lab.email}"
}
