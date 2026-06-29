# Cloud Logging: extended _Default retention plus export sinks to the logs bucket. The
# collectors read Cloud Logging directly; the audit sink also makes logging_posture report
# that audit logs are exported.
#
# Targets: logging_posture (audit sink presence), plus durable export of every log stream

resource "google_logging_project_bucket_config" "default" {
  project        = var.project_id
  location       = "global"
  bucket_id      = "_Default"
  retention_days = 30
  depends_on     = [google_project_service.apis]
}

resource "google_logging_project_sink" "audit" {
  name                   = "${local.name}auditsink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "logName:\"cloudaudit.googleapis.com\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "vpcflow" {
  name                   = "${local.name}vpcflowsink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "logName:\"compute.googleapis.com%2Fvpc_flows\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "firewall" {
  name                   = "${local.name}firewallsink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "logName:\"compute.googleapis.com%2Ffirewall\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "loadbalancer" {
  name                   = "${local.name}lbsink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "resource.type=\"http_load_balancer\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "vm" {
  name                   = "${local.name}vmsink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "resource.type=\"gce_instance\" AND NOT logName:\"compute.googleapis.com%2Fvpc_flows\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "functions" {
  name                   = "${local.name}functionsink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "resource.type=\"cloud_function\" OR resource.type=\"cloud_run_revision\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "dns" {
  name                   = "${local.name}dnssink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "resource.type=\"dns_query\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

resource "google_logging_project_sink" "nat" {
  name                   = "${local.name}natsink"
  destination            = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter                 = "logName:\"compute.googleapis.com%2Fnat_flows\""
  unique_writer_identity = true
  depends_on             = [google_project_service.apis]
}

# Each sink's writer identity needs object-create on the logs bucket.
resource "google_storage_bucket_iam_member" "sink_writer" {
  for_each = {
    audit        = google_logging_project_sink.audit.writer_identity
    vpcflow      = google_logging_project_sink.vpcflow.writer_identity
    firewall     = google_logging_project_sink.firewall.writer_identity
    loadbalancer = google_logging_project_sink.loadbalancer.writer_identity
    vm           = google_logging_project_sink.vm.writer_identity
    functions    = google_logging_project_sink.functions.writer_identity
    dns          = google_logging_project_sink.dns.writer_identity
    nat          = google_logging_project_sink.nat.writer_identity
  }
  bucket = google_storage_bucket.logs.name
  role   = "roles/storage.objectCreator"
  member = each.value
}
