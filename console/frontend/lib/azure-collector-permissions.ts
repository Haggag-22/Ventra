/** Read-only permissions Ventra needs for Azure connection test and collection. */

export type AzurePermissionGroup = {
  label: string;
  permissions: string[];
};

/** Microsoft Graph application permissions (azure-collector-graph.json). */
export const AZURE_GRAPH_PERMISSION_GROUP: AzurePermissionGroup = {
  label: "Microsoft Graph",
  permissions: [
    "AuditLog.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "Application.Read.All",
  ],
};

/**
 * ARM and Graph permissions for every Azure collector.
 * Sourced from artifacts/azure required_actions and docs/iam-policies/azure-collector-readonly.json.
 */
export const AZURE_COLLECTOR_PERMISSION_GROUPS: AzurePermissionGroup[] = [
  {
    label: "Subscription",
    permissions: ["Microsoft.Resources/subscriptions/read"],
  },
  {
    label: "Resource graph",
    permissions: ["Microsoft.ResourceGraph/resources/read"],
  },
  {
    label: "Activity log",
    permissions: [
      "Microsoft.Insights/eventtypes/values/read",
      "Microsoft.Insights/ActivityLogs/read",
    ],
  },
  {
    label: "Diagnostic settings",
    permissions: [
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Resources/subscriptions/resources/read",
    ],
  },
  {
    label: "NSG and VNet flow",
    permissions: [
      "Microsoft.Network/networkWatchers/read",
      "Microsoft.Network/networkWatchers/flowLogs/read",
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "Azure Firewall",
    permissions: [
      "Microsoft.Network/azureFirewalls/read",
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "Application Gateway",
    permissions: [
      "Microsoft.Network/applicationGateways/read",
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "Front Door",
    permissions: [
      "Microsoft.Network/frontDoors/read",
      "Microsoft.Cdn/profiles/read",
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "DNS",
    permissions: [
      "Microsoft.Network/dnsZones/read",
      "Microsoft.Network/privateDnsZones/read",
      "Microsoft.Network/dnsResolverEndpoints/read",
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "Storage access",
    permissions: [
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "Key Vault",
    permissions: [
      "Microsoft.KeyVault/vaults/read",
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "AKS audit",
    permissions: [
      "Microsoft.ContainerService/managedClusters/read",
      "Microsoft.Insights/DiagnosticSettings/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
  },
  {
    label: "Defender",
    permissions: [
      "Microsoft.Security/alerts/read",
      "Microsoft.Security/locations/alerts/read",
    ],
  },
  {
    label: "RBAC",
    permissions: [
      "Microsoft.Authorization/roleDefinitions/read",
      "Microsoft.Authorization/roleAssignments/read",
    ],
  },
  AZURE_GRAPH_PERMISSION_GROUP,
];
