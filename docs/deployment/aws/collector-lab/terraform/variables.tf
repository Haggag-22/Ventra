variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Primary region for the collector lab."
}

variable "project" {
  type        = string
  default     = "ventra-lab"
  description = "Name prefix for lab resources."
}

variable "case_id" {
  type        = string
  default     = "CASE-LAB-AWS"
  description = "Case id tag tying resources to one investigation story."
}

variable "victim_user" {
  type        = string
  default     = "ventra-lab-dbadmin"
  description = "IAM user representing the compromised dbadmin account."
}

variable "enable_eks" {
  type        = bool
  default     = true
  description = "Provision a minimal EKS cluster for eks_audit collector (adds cost)."
}

variable "enable_detective" {
  type        = bool
  default     = true
  description = "Enable Amazon Detective (requires GuardDuty, adds cost)."
}

variable "enable_macie" {
  type        = bool
  default     = true
  description = "Enable Amazon Macie."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Extra tags applied to all resources."
}
