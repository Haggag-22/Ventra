# Compute: a public web VM and a private (NAT-only) VM, both running the Ops Agent and a
# small traffic generator that drives the log-based collectors. Plus a data disk + snapshot.
#
# Targets: gce, vm_logs, vpc_flow, firewall_logs, cloud_nat, load_balancer,
#          cloud_functions, api_gateway, cloud_dns, secret_manager, storage_access,
#          bigquery_audit, cloud_sql, gke_audit, cloud_monitoring
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
    network_ip = "10.60.0.20"
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
    ventra-apigw-host         = try(google_api_gateway_gateway.lab[0].default_hostname, "")
    ventra-secret             = try(google_secret_manager_secret.lab[0].secret_id, "")
    ventra-bucket             = google_storage_bucket.app.name
    ventra-bq-dataset         = try(google_bigquery_dataset.lab[0].dataset_id, "")
    ventra-bq-table             = try(google_bigquery_table.lab[0].table_id, "")
    ventra-sql-host             = try(google_sql_database_instance.lab[0].public_ip_address, "")
    ventra-sql-user             = try(google_sql_user.lab[0].name, "")
    ventra-sql-pass             = try(random_password.cloud_sql_lab[0].result, "")
    ventra-sql-db               = try(google_sql_database.lab[0].name, "")
    ventra-private-ip           = "10.60.0.21"
    ventra-dns-host             = "host.ventra.internal."
    ventra-gke-cluster          = try(google_container_cluster.lab[0].name, "")
    ventra-gke-location         = var.zone
  }

  metadata_startup_script = <<STARTUP
#!/bin/bash
set -euo pipefail
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh || true
bash add-google-cloud-ops-agent-repo.sh --also-install || true
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y nginx curl dnsutils postgresql-client iputils-ping || true
echo "ventra lab web" > /var/www/html/index.html || true
systemctl enable nginx || true
systemctl restart nginx || true
mkdir -p /var/lib/ventra

cat >/opt/ventratraffic.sh <<'EOS'
#!/bin/bash
set -uo pipefail
LOG=/var/log/ventratraffic.log
exec >>"$LOG" 2>&1
echo "=== $(date -Is) ventratraffic start ==="
md() { curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1" 2>/dev/null || true; }
run() { echo "+ $*"; "$@" || echo "  (non-fatal exit $?)"; }
TOKEN=$(curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' || true)
PROJECT=$(md ventra-project)
LB=$(md ventra-lb-ip)
FN=$(md ventra-fn-uri)
APIGW=$(md ventra-apigw-host)
SECRET=$(md ventra-secret)
BUCKET=$(md ventra-bucket)
BQ_DATASET=$(md ventra-bq-dataset)
BQ_TABLE=$(md ventra-bq-table)
SQL_HOST=$(md ventra-sql-host)
SQL_USER=$(md ventra-sql-user)
SQL_PASS=$(md ventra-sql-pass)
SQL_DB=$(md ventra-sql-db)
PRIVATE_IP=$(md ventra-private-ip)
DNS_HOST=$(md ventra-dns-host)
GKE_CLUSTER=$(md ventra-gke-cluster)
GKE_LOCATION=$(md ventra-gke-location)
run host "$DNS_HOST"
run host metadata.google.internal
run getent hosts "$DNS_HOST"
if [ -n "$LB" ]; then run curl -sf -m 10 -H "User-Agent: ventra-lab-traffic" "http://$LB/"; fi
run curl -sf -m 5 "http://127.0.0.1/"
if [ -n "$PRIVATE_IP" ]; then
  run ping -c 2 -W 2 "$PRIVATE_IP"
  run curl -sf -m 5 "http://$PRIVATE_IP/" || true
fi
if [ -n "$APIGW" ]; then run curl -sf -m 10 "https://$APIGW/hello"; fi
if [ -n "$FN" ] && [ -n "$TOKEN" ]; then run curl -sf -m 10 -H "Authorization: Bearer $TOKEN" "$FN"; fi
if [ -n "$SECRET" ] && [ -n "$TOKEN" ]; then
  run curl -sf -m 10 -H "Authorization: Bearer $TOKEN" "https://secretmanager.googleapis.com/v1/projects/$PROJECT/secrets/$SECRET/versions/latest:access"
fi
if [ -n "$BUCKET" ] && [ -n "$TOKEN" ]; then
  run curl -sf -m 10 -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o"
  run curl -sf -m 10 -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/download/storage/v1/b/$BUCKET/o/samples%2Fdemo.csv?alt=media"
fi
if [ -n "$BQ_DATASET" ] && [ -n "$BQ_TABLE" ] && [ -n "$TOKEN" ]; then
  QUERY="SELECT id, value FROM \`$PROJECT.$BQ_DATASET.$BQ_TABLE\` LIMIT 5"
  PAYLOAD=$(printf '{"configuration":{"query":{"query":"%s","useLegacySql":false}}}' "$QUERY")
  run curl -sf -m 30 -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST "https://bigquery.googleapis.com/bigquery/v2/projects/$PROJECT/jobs" -d "$PAYLOAD"
fi
if [ -n "$SQL_HOST" ] && [ -n "$SQL_USER" ] && [ -n "$SQL_PASS" ] && [ -n "$SQL_DB" ]; then
  export PGPASSWORD="$SQL_PASS"
  run psql -h "$SQL_HOST" -U "$SQL_USER" -d "$SQL_DB" -c "SELECT 1 AS ventra_ping;" -t
  run psql -h "$SQL_HOST" -U "$SQL_USER" -d "$SQL_DB" -c "SELECT now();" -t
  unset PGPASSWORD
fi
if [ -n "$GKE_CLUSTER" ] && [ -n "$TOKEN" ]; then
  run curl -sf -m 15 -H "Authorization: Bearer $TOKEN" "https://container.googleapis.com/v1/projects/$PROJECT/locations/$GKE_LOCATION/clusters/$GKE_CLUSTER"
fi
COUNT=$(cat /var/lib/ventra/run_count 2>/dev/null || echo 0)
COUNT=$((COUNT + 1))
echo "$COUNT" > /var/lib/ventra/run_count
if [ $((COUNT % 12)) -eq 0 ]; then
  echo "+ CPU stress window (70s) for monitoring alert"
  timeout 70s sh -c 'while :; do :; done' || true
fi
echo "=== $(date -Is) ventratraffic done ==="
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
OnBootSec=120
OnUnitActiveSec=300
[Install]
WantedBy=timers.target
EOS

systemctl daemon-reload || true
systemctl enable --now ventratraffic.timer || true
sleep 30
/opt/ventratraffic.sh || true
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
    network_ip = "10.60.0.21"
  }

  service_account {
    email  = google_service_account.lab.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    google-logging-enabled    = "true"
    google-monitoring-enabled = "true"
    ventra-lb-ip              = google_compute_global_address.lb.address
    ventra-web-ip             = "10.60.0.20"
    ventra-dns-host           = "host.ventra.internal."
  }

  metadata_startup_script = <<STARTUP
#!/bin/bash
set -euo pipefail
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh || true
bash add-google-cloud-ops-agent-repo.sh --also-install || true
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y nginx curl dnsutils iputils-ping || true
echo "ventra lab private" > /var/www/html/index.html || true
systemctl enable nginx || true
systemctl restart nginx || true

cat >/opt/ventraegress.sh <<'EOS'
#!/bin/bash
set -uo pipefail
LOG=/var/log/ventraegress.log
exec >>"$LOG" 2>&1
echo "=== $(date -Is) ventraegress start ==="
md() { curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1" 2>/dev/null || true; }
run() { echo "+ $*"; "$@" || echo "  (non-fatal exit $?)"; }
LB=$(md ventra-lb-ip)
WEB_IP=$(md ventra-web-ip)
DNS_HOST=$(md ventra-dns-host)
run host "$DNS_HOST"
run host metadata.google.internal
run curl -sf -m 10 https://www.google.com/generate_204
run curl -sf -m 10 https://cloud.google.com/robots.txt
if [ -n "$LB" ]; then run curl -sf -m 10 "http://$LB/"; fi
if [ -n "$WEB_IP" ]; then
  run ping -c 2 -W 2 "$WEB_IP"
  run curl -sf -m 10 "http://$WEB_IP/"
fi
echo "=== $(date -Is) ventraegress done ==="
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
OnBootSec=120
OnUnitActiveSec=300
[Install]
WantedBy=timers.target
EOS

systemctl daemon-reload || true
systemctl enable --now ventraegress.timer || true
sleep 30
/opt/ventraegress.sh || true
STARTUP
}


resource "google_compute_instance" "mirror_collector" {
  count        = var.enable_packet_mirroring ? 1 : 0
  name         = "${local.name}mirror"
  machine_type = "e2-micro"
  zone         = var.zone
  tags         = ["web"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
  }

  service_account {
    email  = google_service_account.lab.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = <<STARTUP
#!/bin/bash
apt-get update -y || true
apt-get install -y nginx || true
echo "ventra mirror collector" > /var/www/html/index.html || true
systemctl enable nginx || true
systemctl restart nginx || true
STARTUP

  depends_on = [null_resource.apis_ready]
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

# Dedicated VM + group for packet-mirror collector ILB. A VM can only belong to
# one load-balanced instance group, so this cannot share the web VM/group.
resource "google_compute_instance_group" "mirror_collector" {
  count     = var.enable_packet_mirroring ? 1 : 0
  name      = "${local.name}mirrorgroup"
  zone      = var.zone
  instances = [google_compute_instance.mirror_collector[0].self_link]
}
