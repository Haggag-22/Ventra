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

  depends_on = [google_project_service.apis]
}

resource "google_sql_database" "lab" {
  count    = var.enable_cloud_sql ? 1 : 0
  name     = "${local.name}db"
  instance = google_sql_database_instance.lab[0].name
}

# Lab credentials only — change or destroy with the lab. Connect via Cloud SQL Studio or the
# Auth Proxy to generate query logs.
resource "google_sql_user" "lab" {
  count    = var.enable_cloud_sql ? 1 : 0
  name     = "${local.name}user"
  instance = google_sql_database_instance.lab[0].name
  password = "ventralabpassword"
}
