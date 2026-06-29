# Cloud Functions Gen2 (Cloud Run under the hood). The traffic generator invokes it so the
# cloud_functions collector has execution logs.
#
# Targets: cloud_functions

data "archive_file" "function" {
  count       = var.enable_functions ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/assets/function"
  output_path = "${path.module}/assets/function.zip"
}

resource "google_storage_bucket_object" "function_source" {
  count  = var.enable_functions ? 1 : 0
  name   = "functionsource.zip"
  bucket = google_storage_bucket.logs.name
  source = data.archive_file.function[0].output_path
}

# Gen2 builds with Cloud Build using the Cloud Build SA and the Compute default SA. Grant
# both the roles a build needs and the ability to act as the function's runtime SA.
locals {
  project_number     = var.project_number
  cloudbuild_sa      = "${local.project_number}@cloudbuild.gserviceaccount.com"
  compute_default_sa = "${local.project_number}-compute@developer.gserviceaccount.com"
  build_sas          = var.enable_functions ? toset([local.cloudbuild_sa, local.compute_default_sa]) : toset([])
}

resource "google_project_iam_member" "build_builder" {
  for_each = local.build_sas
  project  = var.project_id
  role     = "roles/cloudbuild.builds.builder"
  member   = "serviceAccount:${each.value}"
}

resource "google_project_iam_member" "build_artifact_writer" {
  for_each = local.build_sas
  project  = var.project_id
  role     = "roles/artifactregistry.writer"
  member   = "serviceAccount:${each.value}"
}

resource "google_project_iam_member" "build_log_writer" {
  for_each = local.build_sas
  project  = var.project_id
  role     = "roles/logging.logWriter"
  member   = "serviceAccount:${each.value}"
}

resource "google_storage_bucket_iam_member" "build_source_reader" {
  for_each = local.build_sas
  bucket   = google_storage_bucket.logs.name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${each.value}"
}

resource "google_service_account_iam_member" "build_act_as_lab" {
  for_each           = local.build_sas
  service_account_id = google_service_account.lab.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${each.value}"
}

resource "google_cloudfunctions2_function" "hello" {
  count    = var.enable_functions ? 1 : 0
  name     = "${local.name}function"
  location = var.region

  build_config {
    runtime     = "nodejs20"
    entry_point = "helloHttp"
    source {
      storage_source {
        bucket = google_storage_bucket.logs.name
        object = google_storage_bucket_object.function_source[0].name
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
    google_project_iam_member.build_builder,
    google_project_iam_member.build_log_writer,
    google_storage_bucket_iam_member.build_source_reader,
    google_service_account_iam_member.build_act_as_lab,
  ]
}

# Let the lab service account invoke the function. The traffic generator calls the function
# with the VM's (lab SA) token, so no public allUsers binding is needed.
resource "google_cloud_run_service_iam_member" "invoker" {
  count    = var.enable_functions ? 1 : 0
  project  = var.project_id
  location = var.region
  service  = google_cloudfunctions2_function.hello[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.lab.email}"
}
