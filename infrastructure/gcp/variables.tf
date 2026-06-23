variable "project_id" {
  type        = string
  description = "GCP project ID — fill in before apply."
  default     = "ventra-collector-lab-CHANGE-ME"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "project_name" {
  type    = string
  default = "ventra-lab"
}

variable "org_id" {
  type        = string
  description = "Organization ID for SCC (scc_findings). Optional."
  default     = ""
}

variable "enable_scc" {
  type        = bool
  description = "Enable Security Command Center at org level (requires org_id + org admin)."
  default     = false
}

variable "enable_gke" {
  type    = bool
  default = false
}

variable "enable_api_gateway" {
  type    = bool
  default = true
}
