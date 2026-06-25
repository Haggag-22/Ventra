# Ensure Azure collector log paths are enabled (VNet flow, diagnostics on in-scope resources).
# NSG flow logs are not created here — Azure blocked new NSG flow logs after 2025-06-30.

# VNet flow logs (vnet_flow) — primary network flow evidence path
resource "azurerm_network_watcher_flow_log" "vnet" {
  name                 = "${local.name}-vnet-flow"
  network_watcher_name = azurerm_network_watcher.lab.name
  resource_group_name  = azurerm_resource_group.lab.name
  target_resource_id   = azurerm_virtual_network.lab.id
  storage_account_id   = azurerm_storage_account.logs.id
  enabled              = true

  retention_policy {
    enabled = true
    days    = 30
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.lab.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.lab.location
    workspace_resource_id = azurerm_log_analytics_workspace.lab.id
    interval_in_minutes   = 10
  }
}

# VM metrics (resource inventory + LA); VM boot logs require AMA on the guest.
resource "azurerm_monitor_diagnostic_setting" "vm" {
  name                       = "${local.name}-vm-diag"
  target_resource_id         = azurerm_linux_virtual_machine.web.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "nic" {
  name                       = "${local.name}-nic-diag"
  target_resource_id         = azurerm_network_interface.web.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_metric {
    category = "AllMetrics"
  }
}
