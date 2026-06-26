
data "google_project" "current" {
  project_id = var.project_id
}

# Gen2 defaults to the Compute Engine SA for builds unless build_config.service_account is set.
locals {
  compute_default_sa = "${data.google_project.current.number}-compute@developer.gserviceaccount.com"
}

# Cloud Functions Gen2 builds via Cloud Build — grant the default build SA access to source + runtime SA.
resource "google_storage_bucket_iam_member" "cloudbuild_source" {
  bucket = google_storage_bucket.logs.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "compute_build_source" {
  bucket = google_storage_bucket.logs.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${local.compute_default_sa}"
}

resource "google_project_iam_member" "cloudbuild_builder" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}

resource "google_project_iam_member" "cloudbuild_artifact_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}

resource "google_project_iam_member" "cloudbuild_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}

resource "google_project_iam_member" "compute_build_builder" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${local.compute_default_sa}"
}

resource "google_project_iam_member" "compute_build_artifact_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${local.compute_default_sa}"
}

resource "google_project_iam_member" "compute_build_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${local.compute_default_sa}"
}

resource "google_service_account_iam_member" "compute_act_as_lab" {
  service_account_id = google_service_account.lab.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${local.compute_default_sa}"
}

resource "google_service_account_iam_member" "cloudbuild_act_as_lab" {
  service_account_id = google_service_account.lab.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}

# Targets: storage_access, cloud_functions, cloud_monitoring

resource "google_storage_bucket" "logs" {
  name                        = "${local.name}-logs-${var.project_id}"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  depends_on                  = [google_project_service.apis]
}

resource "google_storage_bucket" "app" {
  name                        = "${local.name}-app-${var.project_id}"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  logging {
    log_bucket        = google_storage_bucket.logs.name
    log_object_prefix = "app-access/"
  }
}

resource "google_storage_bucket_object" "sample" {
  name    = "samples/demo-export.csv"
  bucket  = google_storage_bucket.app.name
  content = "id,value\n1,demo\n"
}

resource "google_storage_bucket_iam_member" "app_reader" {
  bucket = google_storage_bucket.app.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.lab.email}"
}

resource "google_cloudfunctions2_function" "hello" {
  name     = "${local.name}-hello"
  location = var.region

  build_config {
    runtime     = "nodejs20"
    entry_point = "helloHttp"
    source {
      storage_source {
        bucket = google_storage_bucket.logs.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    available_memory      = "256M"
    ingress_settings      = "ALLOW_ALL"
    service_account_email = google_service_account.lab.email
  }

  depends_on = [
    google_project_service.apis,
    google_project_iam_member.cloudbuild_builder,
    google_project_iam_member.cloudbuild_log_writer,
    google_project_iam_member.compute_build_builder,
    google_service_account_iam_member.cloudbuild_act_as_lab,
    google_service_account_iam_member.compute_act_as_lab,
    google_storage_bucket_iam_member.cloudbuild_source,
    google_storage_bucket_iam_member.compute_build_source,
  ]
}

resource "google_storage_bucket_object" "function_source" {
  name   = "function-source.zip"
  bucket = google_storage_bucket.logs.name
  source = "${path.module}/assets/function.zip"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "${local.name}-email"
  type         = "email"
  labels = {
    email_address = "alerts@example.com"
  }
  depends_on = [google_project_service.apis]
}

resource "google_monitoring_alert_policy" "uptime" {
  display_name = "${local.name}-vm-cpu"
  combiner     = "OR"

  conditions {
    display_name = "CPU high"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.9
      duration        = "60s"
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]
  depends_on            = [google_project_service.apis]
}
