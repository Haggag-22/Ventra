# Targets: key_vault, aks_audit

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "lab" {
  name                       = "${substr(replace(local.name, "-", ""), 0, 20)}kv"
  location                   = azurerm_resource_group.lab.location
  resource_group_name        = azurerm_resource_group.lab.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = ["Get", "List", "Set", "Delete"]
    key_permissions    = ["Get", "List", "Create", "Delete"]
  }
}

resource "azurerm_key_vault_secret" "demo" {
  name         = "demo-secret"
  value        = "PLACEHOLDER_ROTATE_AFTER_APPLY"
  key_vault_id = azurerm_key_vault.lab.id
}

resource "azurerm_monitor_diagnostic_setting" "keyvault" {
  name                       = "${local.name}-kv-diag"
  target_resource_id         = azurerm_key_vault.lab.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category_group = "allLogs"
  }
}

resource "azurerm_subnet" "aks" {
  count                = var.enable_aks ? 1 : 0
  name                 = "aks"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 4, 4)]
}

resource "azurerm_kubernetes_cluster" "lab" {
  count               = var.enable_aks ? 1 : 0
  name                = "${local.name}-aks"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  dns_prefix          = local.name
  kubernetes_version  = var.aks_kubernetes_version != "" ? var.aks_kubernetes_version : null

  default_node_pool {
    name           = "default"
    node_count     = 1
    vm_size        = "Standard_B2s"
    vnet_subnet_id = azurerm_subnet.aks[0].id
  }

  identity {
    type = "SystemAssigned"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  }
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  count                      = var.enable_aks ? 1 : 0
  name                       = "${local.name}-aks-diag"
  target_resource_id         = azurerm_kubernetes_cluster.lab[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category = "kube-audit"
  }
  enabled_log {
    category = "kube-audit-admin"
  }
}
