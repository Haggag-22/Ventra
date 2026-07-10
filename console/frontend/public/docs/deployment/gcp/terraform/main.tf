terraform {
  required_version = ">= 1.3"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project where the service account is created."
}

variable "service_account_id" {
  type        = string
  default     = "ventra-collector"
  description = "Service account account_id (short name)."
}

variable "display_name" {
  type        = string
  default     = "Ventra Collector"
  description = "Human readable service account name."
}

variable "target_projects" {
  type        = list(string)
  description = "Projects to grant the Ventra collector role on."
}

locals {
  ventra_permissions = [
    "bigquery.datasets.get",
    "bigquery.jobs.create",
    "bigquery.tables.get",
    "bigquery.tables.getData",
    "bigquery.tables.list",
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
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "securitycenter.findings.list",
    "securitycenter.sources.list",
    "storage.buckets.get",
    "storage.objects.get",
    "storage.objects.list",
  ]
}

resource "google_service_account" "ventra_collector" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = var.display_name
}

resource "google_project_iam_custom_role" "ventra_collector" {
  project     = var.project_id
  role_id     = "ventraCollectorReadOnly"
  title       = "Ventra Collector Read Only"
  description = "Read-only permissions for Ventra GCP forensic collectors."
  permissions = local.ventra_permissions
}

resource "google_project_iam_member" "ventra_collector" {
  for_each = toset(var.target_projects)
  project  = each.value
  role     = google_project_iam_custom_role.ventra_collector.id
  member   = "serviceAccount:${google_service_account.ventra_collector.email}"
}

output "service_account_email" {
  value       = google_service_account.ventra_collector.email
  description = "Service account email. Create a JSON key in GCP Console if required."
}

output "custom_role_id" {
  value       = google_project_iam_custom_role.ventra_collector.id
  description = "Custom role ID bound on target projects."
}
