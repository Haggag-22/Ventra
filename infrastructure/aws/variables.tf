variable "region" {
  type        = string
  description = "Primary AWS region for the collector lab."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Prefix for resource names."
  default     = "ventra-lab"
}

variable "environment" {
  type    = string
  default = "collector-test"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

# --- Cost / scope toggles ----------------------------------------------------

variable "enable_eks" {
  type        = bool
  description = "EKS cluster (eks_audit). ~$75+/mo."
  default     = true
}

variable "enable_detective" {
  type        = bool
  description = "Amazon Detective graph (detective)."
  default     = true
}

variable "enable_macie" {
  type        = bool
  description = "Macie + S3 classification (macie)."
  default     = true
}

variable "enable_inspector" {
  type        = bool
  description = "Inspector v2 (inspector2)."
  default     = true
}

variable "enable_cloudfront" {
  type    = bool
  default = true
}

variable "enable_route53_resolver" {
  type    = bool
  default = true
}

variable "cloudtrail_multi_region" {
  type    = bool
  default = true
}

variable "use_existing_account_services" {
  type        = bool
  description = "Skip creating account-level services (GuardDuty, Macie, Config recorder, Inspector) when they already exist in the account."
  default     = true
}
