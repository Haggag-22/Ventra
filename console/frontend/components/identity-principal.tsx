"use client";

import type { IamPolicyEntry } from "@/lib/iam-policies";
import { cn } from "@/lib/utils";
import { FileKey2 } from "lucide-react";
import { useState } from "react";
import { IamPolicyDrawer } from "./iam-policy-drawer";

/**
 * Identity panel principal — click to open attached IAM policies.
 */
export function IdentityPrincipal({
  label,
  principalType,
  policies,
  className,
  mono = true,
}: {
  label: string;
  principalType: "user" | "role";
  policies: IamPolicyEntry[];
  className?: string;
  mono?: boolean;
}) {
  const [drawerOpen, setDrawerOpen] = useState(false);

  if (!label) return <span className="text-fg-subtle">—</span>;

  const policyHint =
    policies.length > 0
      ? `${policies.length} polic${policies.length === 1 ? "y" : "ies"} — click to view`
      : "No policies in snapshot — click for details";

  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setDrawerOpen(true);
        }}
        className={cn(
          "inline-flex max-w-full items-center gap-1 rounded px-1 -mx-1 text-left hover:bg-accent/10 hover:text-accent transition-colors",
          mono && "mono text-xs",
          className,
        )}
        title={policyHint}
      >
        <FileKey2 className="h-3 w-3 shrink-0 opacity-60" />
        <span className="truncate">{label}</span>
        {policies.length > 0 && (
          <span className="shrink-0 rounded bg-surface-2 px-1.5 py-0.5 text-2xs text-fg-subtle">
            {policies.length}
          </span>
        )}
      </button>

      {drawerOpen && (
        <IamPolicyDrawer
          principal={label}
          principalType={principalType}
          policies={policies}
          onClose={() => setDrawerOpen(false)}
        />
      )}
    </>
  );
}
