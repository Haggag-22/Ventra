# Core: enabled APIs, naming locals, lab service account + key, custom read-only role,
# project IAM, and Cloud Audit Logs data-access config.
#
# Targets: project, iam_policy, cloud_audit_admin, cloud_audit_system, cloud_audit_data, login_events

locals {
  # Every resource name is built from these. Letters only — no dashes, no numbers.
  name = var.name_prefix

  # A letters-only token derived from the project id, used only where GCP demands a
  # globally unique name (Cloud Storage buckets, Cloud SQL, BigQuery job ids). Strips
  # every digit and dash from the project id so the result stays letters-only.
  token = lower(replace(var.project_id, "/[^a-zA-Z]/", ""))
}


# Run ./bootstrap-apis.sh before apply.
resource "null_resource" "apis_ready" {
  triggers = { project_id = var.project_id }
}

# -- Lab service account: enumerated by iam_policy, used by the VMs and the function. --

resource "google_service_account" "lab" {
  account_id   = "${local.name}sa"
  display_name = "Ventra lab service account"
  depends_on   = [null_resource.apis_ready]
}

# A user-managed key so iam_policy has key metadata to enumerate. The private key lands
# in Terraform state — fine for a throwaway lab, but destroy the lab when finished.
resource "google_service_account_key" "lab" {
  service_account_id = google_service_account.lab.name
}

# Custom read-only role mirroring docs/iam-policies/gcp-collector-readonly.json, plus the
# monitoring permission cloud_monitoring needs. iam_policy enumerates it as a custom role.
resource "google_project_iam_custom_role" "collector" {
  role_id     = "${local.name}collectorreadonly"
  title       = "Ventra Collector Read Only"
  description = "Least-privilege permissions for the Ventra GCP collectors."
  permissions = [
    "compute.disks.list",
    "compute.firewalls.list",
    "compute.instances.list",
    "compute.networks.list",
    "compute.packetMirrorings.list",
    "compute.routes.list",
    "compute.securityPolicies.list",
    "compute.snapshots.list",
    "compute.subnetworks.list",
    "container.clusters.list",
    "iam.roles.list",
    "iam.serviceAccountKeys.list",
    "iam.serviceAccounts.getIamPolicy",
    "iam.serviceAccounts.list",
    "logging.logEntries.list",
    "logging.logs.list",
    "logging.sinks.list",
    "monitoring.alertPolicies.list",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "securitycenter.findings.list",
    "securitycenter.sources.list",
  ]
}

# Bindings give iam_policy a non-trivial project policy to snapshot.
resource "google_project_iam_member" "lab_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.lab.email}"
}

resource "google_project_iam_member" "lab_collector_role" {
  project = var.project_id
  role    = google_project_iam_custom_role.collector.id
  member  = "serviceAccount:${google_service_account.lab.email}"
}

# Roles the lab VM uses to generate data-access logs (secret read, storage read, BigQuery query).
resource "google_project_iam_member" "lab_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.lab.email}"
}

resource "google_project_iam_member" "lab_storage_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.lab.email}"
}

resource "google_project_iam_member" "lab_bigquery_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.lab.email}"
}

resource "google_project_iam_member" "lab_bigquery_viewer" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = "serviceAccount:${google_service_account.lab.email}"
}

resource "google_project_iam_member" "lab_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.lab.email}"
}

resource "google_project_iam_member" "lab_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.lab.email}"
}

# -- Cloud Audit Logs: turn on Data Access logging so cloud_audit_data, secret_manager,
#    bigquery_audit, storage_access, and login_events have records to collect. --

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

  depends_on = [null_resource.apis_ready]
}
