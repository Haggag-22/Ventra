# Ensure all Azure collector log paths are enabled (VNet + NSG flow, diagnostics everywhere).

# NSG flow logs (nsg_flow)
resource "azurerm_network_watcher_flow_log" "nsg" {
  name                 = "${local.name}-nsg-flow"
  network_watcher_name = azurerm_network_watcher.lab.name
  resource_group_name  = azurerm_resource_group.lab.name
  target_resource_id   = azurerm_network_security_group.lab.id
  storage_account_id   = azurerm_storage_account.logs.id
  enabled              = true

  retention_policy {
    enabled = true
    days    = 30
  }
}

# VNet flow logs (vnet_flow) — separate target from NSG
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

# Activity log → Storage + Log Analytics (activity_log, storage_access)
resource "azurerm_monitor_diagnostic_setting" "subscription_storage" {
  name                       = "${local.name}-activity-storage"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  storage_account_id         = azurerm_storage_account.logs.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
}

# DNS query/audit logs (dns, diag_posture)
resource "azurerm_monitor_diagnostic_setting" "dns" {
  name                       = "${local.name}-dns-diag"
  target_resource_id         = azurerm_dns_zone.lab.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  storage_account_id         = azurerm_storage_account.logs.id

  enabled_log {
    category_group = "allLogs"
  }
}

# VM boot/diagnostic logs (resource_graph inventory + LA)
resource "azurerm_monitor_diagnostic_setting" "vm" {
  name                       = "${local.name}-vm-diag"
  target_resource_id         = azurerm_linux_virtual_machine.web.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  storage_account_id         = azurerm_storage_account.logs.id

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

# AKS — full audit log categories
resource "azurerm_monitor_diagnostic_setting" "aks_all" {
  count                      = var.enable_aks ? 1 : 0
  name                       = "${local.name}-aks-all"
  target_resource_id         = azurerm_kubernetes_cluster.lab[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  storage_account_id         = azurerm_storage_account.logs.id

  enabled_log {
    category_group = "allLogs"
  }
}

# Logs storage account self-diagnostics
resource "azurerm_monitor_diagnostic_setting" "logs_storage" {
  name                       = "${local.name}-logsacct-diag"
  target_resource_id         = azurerm_storage_account.logs.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category_group = "allLogs"
  }
}
