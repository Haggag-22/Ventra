# BigQuery dataset + table. Creation shows up as bigquery_resource activity, and the VM's
# query jobs produce data-access audit logs.
#
# Targets: bigquery_audit

resource "google_bigquery_dataset" "lab" {
  count                      = var.enable_bigquery ? 1 : 0
  dataset_id                 = "${local.name}dataset"
  friendly_name              = "Ventra lab dataset"
  location                   = var.region
  delete_contents_on_destroy = true
  depends_on                 = [google_project_service.apis]
}

resource "google_bigquery_table" "lab" {
  count               = var.enable_bigquery ? 1 : 0
  dataset_id          = google_bigquery_dataset.lab[0].dataset_id
  table_id            = "${local.name}table"
  deletion_protection = false

  schema = jsonencode([
    { name = "id", type = "INTEGER", mode = "NULLABLE" },
    { name = "value", type = "STRING", mode = "NULLABLE" },
  ])
}
