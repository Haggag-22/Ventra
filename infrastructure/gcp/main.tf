resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  suffix = random_id.suffix.hex
  name   = "${var.project_name}-${local.suffix}"
}

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "logging.googleapis.com",
    "storage.googleapis.com",
    "cloudfunctions.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "apigateway.googleapis.com",
    "servicecontrol.googleapis.com",
    "servicemanagement.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "monitoring.googleapis.com",
    "securitycenter.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
