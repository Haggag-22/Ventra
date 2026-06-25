# Targets: storage_access, vnet_flow (flow logs to storage)

resource "azurerm_storage_account" "logs" {
  name                     = replace("${local.name}logs", "-", "")
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  blob_properties {
    delete_retention_policy { days = 7 }
  }
}

resource "azurerm_storage_account" "app" {
  name                     = replace("${local.name}app", "-", "")
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_container" "exports" {
  name                  = "customer-exports"
  storage_account_id    = azurerm_storage_account.app.id
  container_access_type = "private"
}

resource "azurerm_storage_blob" "sample" {
  name                 = "sample-export.csv"
  storage_container_id = azurerm_storage_container.exports.id
  type                 = "Block"
  source_content       = "id,value\n1,demo\n"
}

resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "${local.name}-storage-diag"
  target_resource_id         = azurerm_storage_account.app.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  storage_account_id         = azurerm_storage_account.logs.id

  # Storage account-level diagnostics support metrics only (logs require blob service target).
  enabled_metric {
    category = "Transaction"
  }
}
