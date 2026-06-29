output "project_id" {
  description = "Project the lab was built in (project collector)."
  value       = var.project_id
}

output "region" {
  value = var.region
}

output "service_account_email" {
  description = "Lab service account (iam_policy collector)."
  value       = google_service_account.lab.email
}

output "custom_role_id" {
  description = "Read-only custom role (iam_policy collector)."
  value       = google_project_iam_custom_role.collector.id
}

output "vpc_name" {
  description = "VPC network (network_posture / vpc_flow collectors)."
  value       = google_compute_network.lab.name
}

output "subnet_name" {
  value = google_compute_subnetwork.lab.name
}

output "load_balancer_ip" {
  description = "External HTTP LB address (load_balancer / cloud_armor collectors)."
  value       = google_compute_global_address.lb.address
}

output "web_vm" {
  description = "Public lab VM (gce / vm_logs collectors)."
  value       = google_compute_instance.web.name
}

output "private_vm" {
  description = "Private NAT-only VM (cloud_nat collector)."
  value       = google_compute_instance.private.name
}

output "logs_bucket" {
  value = google_storage_bucket.logs.name
}

output "app_bucket" {
  description = "App bucket (storage_access collector)."
  value       = google_storage_bucket.app.name
}

output "cloud_function_uri" {
  description = "Cloud Function URL (cloud_functions collector)."
  value       = try(google_cloudfunctions2_function.hello[0].service_config[0].uri, null)
}

output "api_gateway_host" {
  description = "API Gateway hostname (api_gateway collector)."
  value       = try(google_api_gateway_gateway.lab[0].default_hostname, null)
}

output "gke_cluster" {
  description = "GKE cluster (gke_audit collector)."
  value       = try(google_container_cluster.lab[0].name, null)
}

output "cloud_sql_instance" {
  description = "Cloud SQL instance (cloud_sql collector)."
  value       = try(google_sql_database_instance.lab[0].name, null)
}

output "bigquery_dataset" {
  description = "BigQuery dataset (bigquery_audit collector)."
  value       = try(google_bigquery_dataset.lab[0].dataset_id, null)
}

output "secret_name" {
  description = "Secret Manager secret (secret_manager collector)."
  value       = try(google_secret_manager_secret.lab[0].secret_id, null)
}

output "dns_zone" {
  description = "Cloud DNS zone (cloud_dns collector)."
  value       = google_dns_managed_zone.lab.name
}

output "acquire_kit_hints" {
  description = "Hints for the Ventra acquire kit."
  value = {
    cloud      = "gcp"
    project_id = var.project_id
    pack       = "baseline-ir-gcp"
  }
}
