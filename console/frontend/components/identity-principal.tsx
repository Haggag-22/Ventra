"use client";

import type { IamPolicyEntry } from "@/lib/iam-policies";
import { cn } from "@/lib/utils";
import { FileKey2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { IamPolicyDrawer } from "./iam-policy-drawer";

/**
 * Identity panel principal — opens policy drawer only (no cross-panel pivots).
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
  const [menuOpen, setMenuOpen] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const hasPolicies = policies.length > 0;

  useEffect(() => {
    if (!menuOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [menuOpen]);

  if (!label) return <span className="text-fg-subtle">—</span>;

  if (!hasPolicies) {
    return (
      <span className={cn(mono && "mono text-xs", className)} title={label}>
        {label}
      </span>
    );
  }

  return (
    <>
      <span ref={ref} className="relative inline-flex">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setMenuOpen((v) => !v);
          }}
          className={cn(
            "inline-flex max-w-full items-center gap-1 rounded px-1 -mx-1 text-left hover:bg-accent/10 hover:text-accent transition-colors",
            mono && "mono text-xs",
            className,
          )}
          title={label}
        >
          <FileKey2 className="h-3 w-3 shrink-0 opacity-50" />
          <span>{label}</span>
        </button>

        {menuOpen && (
          <div className="absolute left-0 top-full z-50 mt-1 w-52 animate-fade-in rounded-lg border border-border bg-surface-2 p-1 shadow-pop">
            <div className="px-2 py-1.5 text-2xs uppercase tracking-wide text-fg-subtle">
              {principalType}
            </div>
            <div className="mono truncate px-2 pb-1.5 text-2xs text-fg">{label}</div>
            <div className="my-1 h-px bg-border" />
            <button
              type="button"
              onClick={() => {
                setMenuOpen(false);
                setDrawerOpen(true);
              }}
              className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg-subtle hover:bg-surface hover:text-fg"
            >
              <FileKey2 className="h-3.5 w-3.5" />
              Show policies ({policies.length})
            </button>
          </div>
        )}
      </span>

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
