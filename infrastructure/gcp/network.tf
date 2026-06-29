# Network: VPC, subnet with flow logs, firewall rules with logging, Cloud NAT, a custom
# route, and packet mirroring.
#
# Targets: vpc_flow, firewall_logs, cloud_nat, network_posture, logging_posture

resource "google_compute_network" "lab" {
  name                    = "${local.name}vpc"
  auto_create_subnetworks = false
  depends_on              = [null_resource.apis_ready]
}

resource "google_compute_subnetwork" "lab" {
  name          = "${local.name}subnet"
  ip_cidr_range = "10.60.0.0/24"
  region        = var.region
  network       = google_compute_network.lab.id

  # Flow logs feed vpc_flow and are detected by logging_posture / network_posture.
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }

  # Secondary ranges for the VPC-native GKE cluster.
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.61.0.0/16"
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.62.0.0/20"
  }
}

# Reserved address for the external HTTP load balancer (see loadbalancer.tf). Reserving it
# here lets the lab VM curl the LB without a dependency cycle.
resource "google_compute_global_address" "lb" {
  name = "${local.name}lbip"
}

# -- Firewall rules (all with logging on, so firewall_logs and logging_posture see them). --

resource "google_compute_firewall" "allowhttp" {
  name    = "${local.name}allowhttp"
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

# Google front-end health-check ranges, so the LB backend reports healthy.
resource "google_compute_firewall" "allowhealth" {
  name    = "${local.name}allowhealth"
  network = google_compute_network.lab.name

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["web"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# IAP range, so you can SSH the private VM without an external IP.
resource "google_compute_firewall" "allowssh" {
  name    = "${local.name}allowssh"
  network = google_compute_network.lab.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["web"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allowinternal" {
  name    = "${local.name}allowinternal"
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

# -- Cloud NAT so the private VM (no external IP) can egress; NAT logging feeds cloud_nat. --

resource "google_compute_router" "lab" {
  name    = "${local.name}router"
  region  = var.region
  network = google_compute_network.lab.id
}

resource "google_compute_router_nat" "lab" {
  name                               = "${local.name}nat"
  router                             = google_compute_router.lab.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ALL"
  }
}

# A custom static route, so network_posture has a non-default route to inventory.
resource "google_compute_route" "lab" {
  name             = "${local.name}route"
  network          = google_compute_network.lab.name
  dest_range       = "192.168.50.0/24"
  next_hop_gateway = "default-internet-gateway"
  priority         = 1000
  tags             = ["web"]
}

# -- Packet mirroring: an internal collector LB plus a mirroring policy for network_posture. --

resource "google_compute_region_health_check" "mirror" {
  count  = var.enable_packet_mirroring ? 1 : 0
  name   = "${local.name}mirrorhealth"
  region = var.region

  tcp_health_check {
    port = 80
  }
}

resource "google_compute_region_backend_service" "mirror" {
  count                 = var.enable_packet_mirroring ? 1 : 0
  name                  = "${local.name}mirrorbackend"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  protocol              = "TCP"
  health_checks         = [google_compute_region_health_check.mirror[0].id]

  backend {
    group          = google_compute_instance_group.mirror_collector[0].self_link
    balancing_mode = "CONNECTION"
  }
}

resource "google_compute_forwarding_rule" "mirror" {
  count                  = var.enable_packet_mirroring ? 1 : 0
  name                   = "${local.name}mirrorrule"
  region                 = var.region
  load_balancing_scheme  = "INTERNAL"
  backend_service        = google_compute_region_backend_service.mirror[0].id
  is_mirroring_collector = true
  network                = google_compute_network.lab.id
  subnetwork             = google_compute_subnetwork.lab.id
  ports                  = ["80"]
}

resource "google_compute_packet_mirroring" "lab" {
  count  = var.enable_packet_mirroring ? 1 : 0
  name   = "${local.name}mirror"
  region = var.region

  network {
    url = google_compute_network.lab.id
  }

  collector_ilb {
    url = google_compute_forwarding_rule.mirror[0].id
  }

  # Mirror by tag (the private VM) rather than the whole subnet, so the collector instances
  # (the mirror collector instance group) are never also a mirrored source — GCP rejects that overlap.
  mirrored_resources {
    tags = ["mirrored"]
  }
}
