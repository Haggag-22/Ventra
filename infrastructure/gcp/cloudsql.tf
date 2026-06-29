# Cloud SQL for PostgreSQL with connection + statement logging. Logs land in Cloud Logging
# under resource.type="cloudsql_database".
#
# Targets: cloud_sql
#
# The instance name carries the project token because Cloud SQL reserves a deleted name for
# up to a week. db-f1-micro keeps it cheap; deletion protection is off so destroy works.

resource "google_sql_database_instance" "lab" {
  count               = var.enable_cloud_sql ? 1 : 0
  name                = "${local.name}sql${local.token}"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = false

  settings {
    tier                        = "db-f1-micro"
    deletion_protection_enabled = false

    ip_configuration {
      ipv4_enabled = true

      # Lab subnet + open ingress so the web VM can connect via public IP and generate logs.
authorized_networks {
        name  = "lab-open"
        value = "0.0.0.0/0"
      }
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_min_duration_statement"
      value = "0"
    }
  }

  depends_on = [null_resource.apis_ready]
}

resource "google_sql_database" "lab" {
  count    = var.enable_cloud_sql ? 1 : 0
  name     = "${local.name}db"
  instance = google_sql_database_instance.lab[0].name
}

resource "random_password" "cloud_sql_lab" {
  count   = var.enable_cloud_sql ? 1 : 0
  length  = 24
  special = false
}

# Lab credentials only — generated at apply time. The web VM traffic script connects with psql.
resource "google_sql_user" "lab" {
  count    = var.enable_cloud_sql ? 1 : 0
  name     = "${local.name}user"
  instance = google_sql_database_instance.lab[0].name
  password = random_password.cloud_sql_lab[0].result
}
