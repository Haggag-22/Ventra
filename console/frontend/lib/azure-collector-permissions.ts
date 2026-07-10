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
    "ActivityFeed.Read",
  ],
};

/** ARM read-only actions grouped for the permission scope panel. */
export const AZURE_COLLECTOR_PERMISSION_GROUPS: AzurePermissionGroup[] = [
  {
    label: "Subscription & resources",
    permissions: [
      "Microsoft.Resources/subscriptions/read",
      "Microsoft.Resources/subscriptions/resources/read",
      "Microsoft.ResourceGraph/resources/read",
    ],
  },
  {
    label: "Activity & diagnostics",
    permissions: [
      "Microsoft.Insights/ActivityLogs/read",
      "Microsoft.Insights/DiagnosticSettings/read",
    ],
  },
  {
    label: "Network",
    permissions: [
      "Microsoft.Network/networkWatchers/read",
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/azureFirewalls/read",
    ],
  },
  {
    label: "Storage & Key Vault",
    permissions: [
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.KeyVault/vaults/read",
    ],
  },
  {
    label: "Security & IAM",
    permissions: [
      "Microsoft.Authorization/roleAssignments/read",
      "Microsoft.Security/alerts/read",
    ],
  },
  AZURE_GRAPH_PERMISSION_GROUP,
];
