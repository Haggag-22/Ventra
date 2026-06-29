# External HTTP(S) load balancer with access logging and a Cloud Armor policy attached.
#
# Targets: load_balancer, cloud_armor

resource "google_compute_security_policy" "armor" {
  name        = "${local.name}armor"
  description = "Ventra lab Cloud Armor policy"

  # Block the documentation range so cloud_armor has an enforced rule to find.
  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["198.51.100.0/24"]
      }
    }
    description = "Deny documentation range"
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow"
  }
}

resource "google_compute_backend_service" "web" {
  name                  = "${local.name}backend"
  protocol              = "HTTP"
  port_name             = "http"
  timeout_sec           = 10
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_health_check.web.id]
  security_policy       = google_compute_security_policy.armor.id

  backend {
    group = google_compute_instance_group.web.self_link
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "web" {
  name            = "${local.name}urlmap"
  default_service = google_compute_backend_service.web.id
}

resource "google_compute_target_http_proxy" "web" {
  name    = "${local.name}httpproxy"
  url_map = google_compute_url_map.web.id
}

resource "google_compute_global_forwarding_rule" "web" {
  name       = "${local.name}forwardrule"
  target     = google_compute_target_http_proxy.web.id
  port_range = "80"
  ip_address = google_compute_global_address.lb.address
}
