variable "region" {
  description = "Single region to deploy the whole test environment into."
  type        = string
  default     = "us-east-1"
}

# ---------------------------------------------------------------------------
# The two master toggles from the roadmap.
# ---------------------------------------------------------------------------

variable "enable_logging" {
  description = <<-EOT
    Master logging switch. true  = every log source has its logging destination wired
    (expect FULL coverage / no false positives). false = resources exist but logging is
    off (expect the collector to CATCH every gap). This is the core validation toggle.
  EOT
  type        = bool
  default     = true
}

variable "enable_expensive" {
  description = <<-EOT
    Convenience gate that turns on ALL Tier 3 hourly-billed resources (Network Firewall,
    OpenSearch, RDS, EKS). Leave false and use the per-service toggles below to bring up
    only what you need, then destroy immediately.
  EOT
  type        = bool
  default     = false
}

# Per-service Tier 3 toggles. Each is ON if its own flag OR enable_expensive is true.
# Use these to build only a subset (e.g. just RDS + EKS) without the others.

variable "enable_rds" {
  description = "Build the RDS instance (+ CloudWatch log exports when enable_logging)."
  type        = bool
  default     = false
}

variable "enable_eks" {
  description = "Build the EKS cluster (+ audit/control-plane logs when enable_logging)."
  type        = bool
  default     = false
}

variable "enable_opensearch" {
  description = "Build the OpenSearch domain (+ log publishing when enable_logging)."
  type        = bool
  default     = false
}

variable "enable_network_firewall" {
  description = "Build the Network Firewall (+ flow logging when enable_logging)."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Finer-grained knobs (sensible defaults; rarely need changing).
# ---------------------------------------------------------------------------

variable "instance_type" {
  description = "EC2 instance type for the Tier 1 traffic/inventory instance."
  type        = string
  default     = "t3.micro"
}

variable "create_ec2" {
  description = "Create the EC2 instance + EBS volume + snapshot (the only Tier 1 hourly compute)."
  type        = bool
  default     = true
}

variable "make_bucket_public" {
  description = "Attach a real anonymous public-read policy to the misconfig bucket (a real exposure)."
  type        = bool
  default     = false
}

variable "make_lambda_public" {
  description = "Attach a wildcard-principal invoke permission to the Lambda (cross-account-invoke test)."
  type        = bool
  default     = false
}

# Account/region-singleton detection services (GuardDuty, Security Hub, Macie,
# Detective, Inspector2) are handled AUTOMATICALLY — see detect.tf. Terraform
# probes the account and only manages the ones not already enabled, so there are
# no manual flags to set and no "already exists" failures.
