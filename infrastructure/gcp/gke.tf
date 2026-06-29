# A small zonal GKE cluster with control-plane (API server) logging enabled, so the
# gke_audit collector finds a cluster with audit logging and k8s_cluster log entries.
#
# Targets: gke_audit
#
# Zonal + one e2-small node keeps cost down. deletion_protection is off so destroy works.

resource "google_container_cluster" "lab" {
  count    = var.enable_gke ? 1 : 0
  name     = "${local.name}cluster"
  location = var.zone

  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = false

  network    = google_compute_network.lab.id
  subnetwork = google_compute_subnetwork.lab.id

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  # APISERVER is what gke_audit checks for; the rest give a realistic control-plane signal.
  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "APISERVER",
      "SCHEDULER",
      "CONTROLLER_MANAGER",
    ]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }

  depends_on = [google_project_service.apis]
}

resource "google_container_node_pool" "lab" {
  count    = var.enable_gke ? 1 : 0
  name     = "${local.name}nodepool"
  location = var.zone
  cluster  = google_container_cluster.lab[0].name

  node_count = 1

  node_config {
    machine_type    = "e2-small"
    disk_size_gb    = 20
    service_account = google_service_account.lab.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}
