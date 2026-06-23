resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  suffix = random_id.suffix.hex
  name   = "${var.project_name}-${local.suffix}"
}

resource "azurerm_resource_group" "lab" {
  name     = "${local.name}-rg"
  location = var.location
  tags     = { Purpose = "ventra-collector-lab" }
}
