# Cloud Logging retention + sinks + Ops Agent bootstrap for vm_logs.

resource "google_logging_project_bucket_config" "default" {
  project        = var.project_id
  location       = "global"
  bucket_id      = "_Default"
  retention_days = 30
  depends_on     = [google_project_service.apis]
}

# _Required is locked/immutable in GCP — retention cannot be changed via Terraform.

resource "google_logging_project_sink" "vpc_flow" {
  name                   = "${local.name}-vpc-flow"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}/vpc-flow"
  filter                 = "resource.type=\"gce_subnetwork\" AND logName:\"compute.googleapis.com%2Fvpc_flows\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "firewall" {
  name                   = "${local.name}-firewall"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}/firewall"
  filter                 = "resource.type=\"gce_firewall_rule\" AND logName:\"compute.googleapis.com%2Ffirewall\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "load_balancer" {
  name                   = "${local.name}-lb"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}/load-balancer"
  filter                 = "resource.type=\"http_load_balancer\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "vm" {
  name                   = "${local.name}-vm"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}/vm"
  filter                 = "resource.type=\"gce_instance\" AND NOT logName:\"compute.googleapis.com%2Fvpc_flows\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "cloud_functions" {
  name                   = "${local.name}-cf"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}/cloud-functions"
  filter                 = "resource.type=\"cloud_function\" OR resource.type=\"cloud_run_revision\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  for_each = {
    vpc_flow        = google_logging_project_sink.vpc_flow.writer_identity
    firewall        = google_logging_project_sink.firewall.writer_identity
    load_balancer   = google_logging_project_sink.load_balancer.writer_identity
    vm              = google_logging_project_sink.vm.writer_identity
    cloud_functions = google_logging_project_sink.cloud_functions.writer_identity
    audit           = google_logging_project_sink.audit.writer_identity
  }
  bucket = google_storage_bucket.logs.name
  role   = "roles/storage.objectCreator"
  member = each.value
}
