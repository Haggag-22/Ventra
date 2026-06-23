# Targets: vpc_flow, firewall_logs, load_balancer, vm_logs

resource "google_compute_network" "lab" {
  name                    = "${local.name}-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "lab" {
  name          = "${local.name}-subnet"
  ip_cidr_range = "10.60.0.0/24"
  region        = var.region
  network       = google_compute_network.lab.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_http" {
  name    = "${local.name}-allow-http"
  network = google_compute_network.lab.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_internal" {
  name    = "${local.name}-allow-internal"
  network = google_compute_network.lab.name

  allow {
    protocol = "icmp"
  }
  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }

  source_ranges = ["10.60.0.0/24"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_address" "lab" {
  name   = "${local.name}-ip"
  region = var.region
}

resource "google_compute_instance" "web" {
  name         = "${local.name}-vm"
  machine_type = "e2-micro"
  zone         = var.zone

  tags = ["web"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    access_config {
      nat_ip = google_compute_address.lab.address
    }
  }

  metadata = {
    google-logging-enabled    = "true"
    google-monitoring-enabled = "true"
  }

  metadata_startup_script = <<-SCRIPT
    #!/bin/bash
    apt-get update
    apt-get install -y nginx curl
    echo ventra-lab > /var/www/html/index.html
    curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
    bash add-google-cloud-ops-agent-repo.sh --also-install
    systemctl enable google-cloud-ops-agent || true
    systemctl start google-cloud-ops-agent || true
  SCRIPT

  service_account {
    email  = google_service_account.lab.email
    scopes = ["cloud-platform"]
  }
}

resource "google_compute_health_check" "web" {
  name = "${local.name}-hc"
  http_health_check {
    port         = 80
    request_path = "/"
  }
}

resource "google_compute_instance_group" "web" {
  name = "${local.name}-ig"
  zone = var.zone

  instances = [google_compute_instance.web.self_link]

  named_port {
    name = "http"
    port = 80
  }
}

resource "google_compute_backend_service" "web" {
  name                  = "${local.name}-backend"
  protocol              = "HTTP"
  port_name             = "http"
  timeout_sec           = 10
  health_checks         = [google_compute_health_check.web.id]
  load_balancing_scheme = "EXTERNAL"

  backend {
    group = google_compute_instance_group.web.self_link
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "web" {
  name            = "${local.name}-url-map"
  default_service = google_compute_backend_service.web.id
}

resource "google_compute_target_http_proxy" "web" {
  name    = "${local.name}-http-proxy"
  url_map = google_compute_url_map.web.id
}

resource "google_compute_global_forwarding_rule" "web" {
  name       = "${local.name}-fwd-rule"
  target     = google_compute_target_http_proxy.web.id
  port_range = "80"
}
