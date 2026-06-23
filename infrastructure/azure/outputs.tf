output "subscription_id" {
  value = var.subscription_id
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "log_analytics_workspace_id" {
  description = "log_analytics collector"
  value       = azurerm_log_analytics_workspace.lab.id
}

output "storage_account_app" {
  description = "storage_access collector"
  value       = azurerm_storage_account.app.name
}

output "vnet_name" {
  description = "vnet_flow collector"
  value       = azurerm_virtual_network.lab.name
}

output "key_vault_name" {
  value = azurerm_key_vault.lab.name
}

output "dns_zone" {
  description = "dns collector"
  value       = azurerm_dns_zone.lab.name
}

output "aks_cluster_name" {
  value = try(azurerm_kubernetes_cluster.lab[0].name, null)
}

output "front_door_endpoint" {
  value = try(azurerm_cdn_frontdoor_endpoint.lab[0].host_name, null)
}

output "acquire_kit_hints" {
  value = {
    cloud           = "azure"
    subscription_id = var.subscription_id
    tenant_id       = data.azurerm_client_config.current.tenant_id
    pack            = "baseline-ir-azure"
  }
}
