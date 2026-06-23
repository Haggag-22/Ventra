output "project_id" {
  description = "project collector"
  value       = var.project_id
}

output "region" {
  value = var.region
}

output "vpc_name" {
  description = "vpc_flow collector"
  value       = google_compute_network.lab.name
}

output "app_bucket" {
  description = "storage_access collector"
  value       = google_storage_bucket.app.name
}

output "logs_bucket" {
  value = google_storage_bucket.logs.name
}

output "load_balancer_ip" {
  description = "load_balancer collector"
  value       = google_compute_global_forwarding_rule.web.ip_address
}

output "cloud_function_name" {
  value = google_cloudfunctions2_function.hello.name
}

output "api_gateway_url" {
  value = try(google_api_gateway_gateway.lab[0].default_hostname, null)
}

output "service_account_email" {
  description = "iam_policy collector"
  value       = google_service_account.lab.email
}

output "acquire_kit_hints" {
  value = {
    cloud      = "gcp"
    project_id = var.project_id
    pack       = "baseline-ir-gcp"
  }
}
