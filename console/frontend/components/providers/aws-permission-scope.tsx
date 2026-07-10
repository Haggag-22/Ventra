"use client";

import { AWS_COLLECTOR_PERMISSION_GROUPS } from "@/lib/aws-collector-permissions";
import { Shield } from "lucide-react";

export function AwsPermissionScope() {
  const groupCount = AWS_COLLECTOR_PERMISSION_GROUPS.length;

  return (
    <div className="rounded-lg border border-border bg-surface-2/40 p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-fg">
        <Shield className="h-4 w-4 text-ok-green" />
        Permission scope
      </div>
      <div className="mt-2 space-y-1.5 text-xs leading-relaxed text-fg-subtle">
        <p>
          <span className="font-medium text-fg">Authentication</span> —{" "}
          <code className="mono text-fg">sts:GetCallerIdentity</code>
        </p>
        <p>
          <span className="font-medium text-fg">Collection</span> — read-only IAM across{" "}
          {groupCount} service areas. Use the collector policy templates linked below.
        </p>
      </div>
    </div>
  );
}
