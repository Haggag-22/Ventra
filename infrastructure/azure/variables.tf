variable "subscription_id" {
  type        = string
  description = "Azure subscription ID — fill in before apply."
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "location" {
  type        = string
  description = "Azure region. eastus2/centralus often have more free-tier VM capacity than eastus."
  default     = "eastus2"
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

variable "vm_size" {
  type        = string
  description = "Lab VM SKU. Standard_B2s avoids common B1s capacity errors on trial subs."
  default     = "Standard_B2s"
}

variable "enable_aks" {
  type        = bool
  description = "AKS cluster (aks_audit). Expensive; blocked on some trial subs."
  default     = false
}

variable "aks_kubernetes_version" {
  type        = string
  description = "AKS version. Leave empty to use the region default supported version."
  default     = ""
}

variable "enable_firewall" {
  type        = bool
  description = "Azure Firewall (azure_firewall). ~$1+/hr."
  default     = false
}

variable "enable_front_door" {
  type        = bool
  description = "Front Door Standard. Not available on Free Trial / Student subscriptions."
  default     = false
}

variable "enable_app_gateway" {
  type        = bool
  description = "Application Gateway v2 + diagnostics."
  default     = true
}

variable "tenant_id" {
  type        = string
  description = "Entra tenant ID for Entra/M365 collectors (manual verification)."
  default     = "00000000-0000-0000-0000-000000000000"
}
