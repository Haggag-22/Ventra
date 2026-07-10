"use client";

import { Shield } from "lucide-react";

export function KubernetesPermissionScope() {
  return (
    <div className="rounded-lg border border-border bg-surface-2/40 p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-fg">
        <Shield className="h-4 w-4 text-ok-green" />
        Permission scope
      </div>
      <div className="mt-2 space-y-1.5 text-xs leading-relaxed text-fg-subtle">
        <p>
          <span className="font-medium text-fg">Authentication</span> — kubeconfig credentials
          with access to the named context.
        </p>
        <p>
          <span className="font-medium text-fg">Collection</span> — read-only RBAC (
          <code className="mono text-fg">get</code>, <code className="mono text-fg">list</code>,{" "}
          <code className="mono text-fg">watch</code>) on core workloads, events, and audit
          resources. No write permissions required.
        </p>
      </div>
    </div>
  );
}
