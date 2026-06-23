variable "subscription_id" {
  type        = string
  description = "Azure subscription ID — fill in before apply."
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "project_name" {
  type    = string
  default = "ventra-lab"
}

variable "environment" {
  type    = string
  default = "collector-test"
}

variable "vnet_cidr" {
  type    = string
  default = "10.50.0.0/16"
}

variable "enable_aks" {
  type        = bool
  description = "AKS cluster (aks_audit). Expensive."
  default     = true
}

variable "enable_firewall" {
  type        = bool
  description = "Azure Firewall (azure_firewall). ~$1+/hr."
  default     = true
}

variable "enable_front_door" {
  type    = bool
  default = true
}

variable "enable_app_gateway" {
  type    = bool
  default = true
}

variable "tenant_id" {
  type        = string
  description = "Entra tenant ID for Entra/M365 collectors (manual verification)."
  default     = "00000000-0000-0000-0000-000000000000"
}
