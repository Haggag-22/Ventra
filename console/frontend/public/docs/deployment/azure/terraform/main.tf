terraform {
  required_version = ">= 1.3"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID for role assignment."
}

variable "role_name" {
  type        = string
  default     = "Ventra Collector Read Only"
  description = "Display name for the custom role."
}

variable "principal_object_id" {
  type        = string
  description = "Object ID of the Ventra service principal (app registration)."
}

locals {
  ventra_actions = [
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/subscriptions/locations/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Resources/subscriptions/resources/read",
    "Microsoft.Insights/ActivityLogs/read",
    "Microsoft.Insights/eventtypes/values/read",
    "Microsoft.Insights/DiagnosticSettings/read",
    "Microsoft.Network/networkWatchers/read",
    "Microsoft.Network/networkWatchers/flowLogs/read",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/azureFirewalls/read",
    "Microsoft.Network/applicationGateways/read",
    "Microsoft.Network/frontDoors/read",
    "Microsoft.Network/dnsZones/read",
    "Microsoft.Network/privateDnsZones/read",
    "Microsoft.Network/dnsResolverEndpoints/read",
    "Microsoft.Cdn/profiles/read",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.ContainerService/managedClusters/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
    "Microsoft.Security/alerts/read",
    "Microsoft.Security/locations/alerts/read",
    "Microsoft.ResourceGraph/resources/read",
    "Microsoft.OperationalInsights/workspaces/read",
    "Microsoft.OperationalInsights/workspaces/query/action",
  ]
  ventra_data_actions = [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
  ]
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

resource "azurerm_role_definition" "ventra_collector" {
  name        = "VentraCollectorReadOnly"
  scope       = "/subscriptions/${var.subscription_id}"
  description = "Read-only ARM permissions for Ventra Azure forensic collection."

  permissions {
    actions          = local.ventra_actions
    not_actions      = []
    data_actions     = local.ventra_data_actions
    not_data_actions = []
  }

  assignable_scopes = ["/subscriptions/${var.subscription_id}"]
}

resource "azurerm_role_assignment" "ventra_collector" {
  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = azurerm_role_definition.ventra_collector.role_definition_resource_id
  principal_id       = var.principal_object_id
}

output "role_definition_id" {
  value       = azurerm_role_definition.ventra_collector.role_definition_resource_id
  description = "Custom role definition ID."
}

output "notes" {
  value       = "Grant Microsoft Graph application permissions separately. See docs/iam-policies/azure-collector-graph.json and admin consent in Entra ID."
  description = "Additional Entra setup required for identity and M365 collectors."
}
