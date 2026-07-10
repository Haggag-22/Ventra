data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = var.region

  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  common_tags = merge({
    Project    = var.project
    ManagedBy  = "ventra-collector-lab"
    CaseId     = var.case_id
    AttackStory = "dbadmin-compromise"
  }, var.tags)

  bucket_suffix = "${local.account_id}-${random_id.suffix.hex}"
}

resource "random_id" "suffix" {
  byte_length = 4
}
