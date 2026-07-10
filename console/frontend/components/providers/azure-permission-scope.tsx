"use client";

import { AZURE_COLLECTOR_PERMISSION_GROUPS } from "@/lib/azure-collector-permissions";
import { Shield } from "lucide-react";

export function AzurePermissionScope() {
  const armGroups = AZURE_COLLECTOR_PERMISSION_GROUPS.filter((g) => g.label !== "Microsoft Graph");

  return (
    <div className="rounded-lg border border-border bg-surface-2/40 p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-fg">
        <Shield className="h-4 w-4 text-ok-green" />
        Permission scope
      </div>
      <div className="mt-2 space-y-1.5 text-xs leading-relaxed text-fg-subtle">
        <p>
          <span className="font-medium text-fg">Authentication</span> — Microsoft Graph token via
          service principal; ARM access via subscription role assignment.
        </p>
        <p>
          <span className="font-medium text-fg">Collection</span> — read-only ARM across{" "}
          {armGroups.length} areas plus Microsoft Graph application permissions. Use the policy
          templates linked below.
        </p>
      </div>
    </div>
  );
}
