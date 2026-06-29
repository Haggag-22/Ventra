# Cloud DNS: a private zone plus a network DNS policy with query logging enabled. VM DNS
# lookups (from the traffic generators) then land in Cloud Logging as dns_query entries.
#
# Targets: cloud_dns

resource "google_dns_managed_zone" "lab" {
  name        = "${local.name}zone"
  dns_name    = "ventra.internal."
  description = "Ventra lab private zone"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.lab.id
    }
  }

  depends_on = [null_resource.apis_ready]
}

resource "google_dns_record_set" "host" {
  name         = "host.${google_dns_managed_zone.lab.dns_name}"
  managed_zone = google_dns_managed_zone.lab.name
  type         = "A"
  ttl          = 300
  rrdatas      = ["10.60.0.2"]
}

# Query logging for everything resolving through this VPC.
resource "google_dns_policy" "lab" {
  name           = "${local.name}dnspolicy"
  enable_logging = true

  networks {
    network_url = google_compute_network.lab.id
  }

  depends_on = [null_resource.apis_ready]
}
