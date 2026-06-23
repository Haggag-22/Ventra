###############################################################################
# Ventra AWS collector lab — provisions logging + inventory for all 22 collectors.
# See README.md and outputs.tf for Acquire kit parameter hints.
###############################################################################

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  name   = "${var.project_name}-${local.suffix}"
  azs    = slice(data.aws_availability_zones.available.names, 0, 2)
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
