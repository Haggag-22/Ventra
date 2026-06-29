# Cloud Storage: a logs bucket and an app bucket with access logging + a sample object.
# Bucket names must be globally unique, so they carry the letters-only project token.
#
# Targets: storage_access, cloud_audit_data, logging_posture

resource "google_storage_bucket" "logs" {
  name                        = "${local.name}logs${local.token}"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  depends_on                  = [null_resource.apis_ready]
}

resource "google_storage_bucket" "app" {
  name                        = "${local.name}app${local.token}"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true

  logging {
    log_bucket        = google_storage_bucket.logs.name
    log_object_prefix = "appaccess"
  }

  depends_on = [null_resource.apis_ready]
}

resource "google_storage_bucket_object" "sample" {
  name    = "samples/demo.csv"
  bucket  = google_storage_bucket.app.name
  content = "id,value\n1,demo\n"
}
