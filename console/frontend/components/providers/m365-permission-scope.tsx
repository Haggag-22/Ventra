"use client";

import { M365_COLLECTOR_PERMISSION_GROUPS } from "@/lib/m365-collector-permissions";
import { Shield } from "lucide-react";

export function M365PermissionScope() {
  return (
    <div className="rounded-lg border border-border bg-surface-2/40 p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-fg">
        <Shield className="h-4 w-4 text-ok-green" />
        Permission scope
      </div>
      <div className="mt-2 space-y-1.5 text-xs leading-relaxed text-fg-subtle">
        <p>
          <span className="font-medium text-fg">Authentication</span> — Microsoft Graph token via
          app registration ({M365_COLLECTOR_PERMISSION_GROUPS.length} permission areas).
        </p>
        <p>
          <span className="font-medium text-fg">Collection</span> — Entra audit, sign-in logs, and
          M365 Unified Audit. Use the policy templates linked below.
        </p>
      </div>
    </div>
  );
}
