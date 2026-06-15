terraform {
  required_version = ">= 1.3"
  required_providers {
    aws      = { source = "hashicorp/aws", version = "~> 5.0" }
    random   = { source = "hashicorp/random", version = "~> 3.0" }
    archive  = { source = "hashicorp/archive", version = "~> 2.0" }
    external = { source = "hashicorp/external", version = "~> 2.0" }
    null     = { source = "hashicorp/null", version = "~> 3.0" }
  }
}

# Single-region by design — the roadmap keeps everything in one region for cost control.
provider "aws" {
  region = var.region

  # Roadmap tag convention: Project=logging-test. Every resource inherits these.
  default_tags {
    tags = {
      Project   = "logging-test"
      ManagedBy = "terraform"
      Purpose   = "ventra-dfir-collector-testing"
      Ephemeral = "true"
    }
  }
}
