/** Microsoft Graph + M365 permissions for M365-only connections. */

export type M365PermissionGroup = {
  label: string;
  permissions: string[];
};

export const M365_COLLECTOR_PERMISSION_GROUPS: M365PermissionGroup[] = [
  {
    label: "Microsoft Graph",
    permissions: [
      "AuditLog.Read.All",
      "Directory.Read.All",
      "User.Read.All",
      "Group.Read.All",
      "Application.Read.All",
      "ActivityFeed.Read",
    ],
  },
  {
    label: "Unified Audit Log",
    permissions: [
      "ActivityFeed.Read (Management Activity API)",
      "Exchange.ManageAsApp (extended search)",
    ],
  },
];
