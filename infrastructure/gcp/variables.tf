variable "project_id" {
  type        = string
  description = "Your GCP project ID. The lab is built inside this project (you provide it)."
}

variable "project_number" {
  type        = string
  description = "GCP project number (Console → Project settings). Avoids a live project lookup during plan."
}

variable "region" {
  type        = string
  description = "Region for regional resources."
  default     = "us-central1"
}

variable "zone" {
  type        = string
  description = "Zone for zonal resources (VMs, GKE)."
  default     = "us-central1-a"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for every resource name. Letters only, no dashes, no numbers."
  default     = "ventra"

  validation {
    condition     = can(regex("^[a-z]+$", var.name_prefix))
    error_message = "name_prefix must be lowercase letters only (no dashes, numbers, or symbols)."
  }
}

variable "alert_email" {
  type        = string
  description = "Email for the Cloud Monitoring notification channel (cloud_monitoring)."
  default     = "alerts@example.com"
}

# -- Component toggles. Default on so the lab covers every collector. Turn off to cut cost. --

variable "enable_functions" {
  type        = bool
  description = "Cloud Functions Gen2 (cloud_functions, api_gateway backend)."
  default     = true
}

variable "enable_api_gateway" {
  type        = bool
  description = "API Gateway in front of the function (api_gateway). Requires enable_functions."
  default     = true
}

variable "enable_gke" {
  type        = bool
  description = "Small zonal GKE cluster with API-server logging (gke_audit)."
  default     = true
}

variable "enable_cloud_sql" {
  type        = bool
  description = "Cloud SQL for PostgreSQL with query logging (cloud_sql)."
  default     = true
}

variable "enable_bigquery" {
  type        = bool
  description = "BigQuery dataset and table (bigquery_audit)."
  default     = true
}

variable "enable_secret_manager" {
  type        = bool
  description = "Secret Manager secret accessed by the lab VM (secret_manager)."
  default     = true
}

variable "enable_packet_mirroring" {
  type        = bool
  description = "Packet mirroring policy + internal collector LB (network_posture)."
  default     = true
}

# -- Organization-scoped (need Organization Admin; off by default). --

variable "org_id" {
  type        = string
  description = "Organization ID for Security Command Center (scc_findings). Optional."
  default     = ""
}

variable "enable_scc" {
  type        = bool
  description = "Create an SCC Pub/Sub export topic (scc_findings). Also requires org_id + Organization Admin."
  default     = true
}
