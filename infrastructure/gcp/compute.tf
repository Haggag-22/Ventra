# Compute: a public web VM and a private (NAT-only) VM, both running the Ops Agent and a
# small traffic generator that drives the log-based collectors. Plus a data disk + snapshot.
#
# Targets: gce, vm_logs, vpc_flow, firewall_logs, cloud_nat, load_balancer,
#          cloud_functions, cloud_dns, secret_manager, storage_access, bigquery_audit
#
# NOTE on heredocs: Terraform interpolates ${...} inside heredocs, so every shell variable
# below is written without braces ($VAR, not ${VAR}) to keep it literal at boot time.

resource "google_compute_disk" "data" {
  name = "${local.name}disk"
  type = "pd-standard"
  zone = var.zone
  size = 10
}

resource "google_compute_snapshot" "data" {
  name        = "${local.name}snapshot"
  source_disk = google_compute_disk.data.id
  zone        = var.zone
}

resource "google_compute_health_check" "web" {
  name = "${local.name}healthcheck"

  http_health_check {
    port         = 80
    request_path = "/"
  }
}

resource "google_compute_instance" "web" {
  name         = "${local.name}web"
  machine_type = "e2-micro"
  zone         = var.zone
  tags         = ["web"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  attached_disk {
    source = google_compute_disk.data.id
  }

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    access_config {}
  }

  service_account {
    email  = google_service_account.lab.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    google-logging-enabled    = "true"
    google-monitoring-enabled = "true"
    ventra-lb-ip              = google_compute_global_address.lb.address
    ventra-project            = var.project_id
    ventra-fn-uri             = try(google_cloudfunctions2_function.hello[0].service_config[0].uri, "")
    ventra-secret             = try(google_secret_manager_secret.lab[0].secret_id, "")
    ventra-bucket             = google_storage_bucket.app.name
  }

  metadata_startup_script = <<STARTUP
#!/bin/bash
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh || true
bash add-google-cloud-ops-agent-repo.sh --also-install || true
apt-get update -y || true
apt-get install -y nginx curl dnsutils || true
echo "ventra lab web" > /var/www/html/index.html || true
systemctl enable nginx || true
systemctl restart nginx || true

cat >/opt/ventratraffic.sh <<'EOS'
#!/bin/bash
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
TOKEN=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
LB=$(md ventra-lb-ip)
FN=$(md ventra-fn-uri)
SECRET=$(md ventra-secret)
BUCKET=$(md ventra-bucket)
PROJECT=$(md ventra-project)
# DNS queries -> cloud_dns
getent hosts metadata.google.internal >/dev/null 2>&1 || true
host www.google.com >/dev/null 2>&1 || true
# Load balancer + firewall + flow logs
[ -n "$LB" ] && curl -s -m 5 "http://$LB/" >/dev/null 2>&1 || true
# Cloud Function (authenticated with the VM's service-account token)
[ -n "$FN" ] && [ -n "$TOKEN" ] && curl -s -m 5 -H "Authorization: Bearer $TOKEN" "$FN" >/dev/null 2>&1 || true
# Secret Manager access -> data_access / secret_manager
[ -n "$SECRET" ] && [ -n "$TOKEN" ] && curl -s -m 5 -H "Authorization: Bearer $TOKEN" "https://secretmanager.googleapis.com/v1/projects/$PROJECT/secrets/$SECRET/versions/latest:access" >/dev/null 2>&1 || true
# Storage object listing -> data_access / storage_access
[ -n "$BUCKET" ] && [ -n "$TOKEN" ] && curl -s -m 5 -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o" >/dev/null 2>&1 || true
# BigQuery query -> data_access / bigquery_audit
[ -n "$TOKEN" ] && curl -s -m 10 -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST "https://bigquery.googleapis.com/bigquery/v2/projects/$PROJECT/jobs" -d '{"configuration":{"query":{"query":"SELECT 1 AS id","useLegacySql":false}}}' >/dev/null 2>&1 || true
EOS
chmod +x /opt/ventratraffic.sh

cat >/etc/systemd/system/ventratraffic.service <<'EOS'
[Unit]
Description=Ventra lab traffic generator
[Service]
Type=oneshot
ExecStart=/opt/ventratraffic.sh
EOS

cat >/etc/systemd/system/ventratraffic.timer <<'EOS'
[Unit]
Description=Run the Ventra lab traffic generator periodically
[Timer]
OnBootSec=90
OnUnitActiveSec=300
[Install]
WantedBy=timers.target
EOS

systemctl daemon-reload || true
systemctl enable --now ventratraffic.timer || true
STARTUP
}

resource "google_compute_instance" "private" {
  name         = "${local.name}private"
  machine_type = "e2-micro"
  zone         = var.zone
  tags         = ["web", "mirrored"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  # No access_config -> no external IP -> egress flows through Cloud NAT (cloud_nat).
  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
  }

  service_account {
    email  = google_service_account.lab.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    google-logging-enabled    = "true"
    google-monitoring-enabled = "true"
    ventra-lb-ip              = google_compute_global_address.lb.address
  }

  metadata_startup_script = <<STARTUP
#!/bin/bash
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh || true
bash add-google-cloud-ops-agent-repo.sh --also-install || true
apt-get update -y || true
apt-get install -y curl dnsutils || true

cat >/opt/ventraegress.sh <<'EOS'
#!/bin/bash
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
LB=$(md ventra-lb-ip)
# DNS + outbound egress via Cloud NAT -> cloud_nat / cloud_dns
host www.google.com >/dev/null 2>&1 || true
curl -s -m 5 https://www.google.com >/dev/null 2>&1 || true
[ -n "$LB" ] && curl -s -m 5 "http://$LB/" >/dev/null 2>&1 || true
EOS
chmod +x /opt/ventraegress.sh

cat >/etc/systemd/system/ventraegress.service <<'EOS'
[Unit]
Description=Ventra lab egress generator
[Service]
Type=oneshot
ExecStart=/opt/ventraegress.sh
EOS

cat >/etc/systemd/system/ventraegress.timer <<'EOS'
[Unit]
Description=Run the Ventra lab egress generator periodically
[Timer]
OnBootSec=90
OnUnitActiveSec=300
[Install]
WantedBy=timers.target
EOS

systemctl daemon-reload || true
systemctl enable --now ventraegress.timer || true
STARTUP
}

resource "google_compute_instance_group" "web" {
  name      = "${local.name}group"
  zone      = var.zone
  instances = [google_compute_instance.web.self_link]

  named_port {
    name = "http"
    port = 80
  }
}
