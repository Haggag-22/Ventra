"use client";

import { Button } from "@/components/ui";
import {
  ACQUIRE_PLATFORM_LABELS,
  acquirePermissionModel,
  isAcquirePlatform,
  type AcquirePlatform,
} from "@/lib/catalog";
import { shortPlatformLabel } from "@/components/providers/types";
import { cn } from "@/lib/utils";
import { List, X } from "lucide-react";
import { useEffect } from "react";
import { createPortal } from "react-dom";

type Props = {
  open: boolean;
  onClose: () => void;
  /** Acquire tabs plus legacy M365 kits that still open this dialog. */
  cloud: AcquirePlatform | "m365";
  actions: string[];
  actionCount: number;
  implicitCount: number;
  /** Render above wizard modals (z-[300]). Use when opened from KitRunWizard or similar. */
  elevated?: boolean;
};

export function IamActionsDialog({
  open,
  onClose,
  cloud,
  actions,
  actionCount,
  implicitCount,
  elevated = false,
}: Props) {
  const model = acquirePermissionModel(cloud);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className={cn(
        "fixed inset-0 flex items-center justify-center bg-black/50 p-4 animate-fade-in",
        elevated ? "z-[400]" : "z-[100]",
      )}
      onMouseDown={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
        role="dialog"
        aria-labelledby="iam-actions-title"
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 id="iam-actions-title" className="flex items-center gap-2 text-sm font-semibold">
            <List className="h-4 w-4 text-fg-subtle" />
            {model} actions —{" "}
            {isAcquirePlatform(cloud) ? ACQUIRE_PLATFORM_LABELS[cloud] : shortPlatformLabel(cloud)}
          </h3>
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="border-b border-border px-4 py-2.5 text-sm text-fg-subtle">
          <span className="mono font-medium text-fg">{actionCount}</span> narrowed action
          {actionCount === 1 ? "" : "s"}
          {implicitCount > 0 && (
            <>
              {" "}
              (+ {implicitCount} implicit collector{implicitCount === 1 ? "" : "s"})
            </>
          )}
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-3">
          {actions.length === 0 ? (
            <p className="text-sm text-fg-subtle">No {model} actions in this preview.</p>
          ) : (
            <ul className="space-y-1.5">
              {actions.map((action) => (
                <li
                  key={action}
                  className="mono rounded-md border border-border/60 bg-surface-2 px-3 py-2 text-sm text-fg"
                >
                  {action}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="flex justify-end border-t border-border px-4 py-3">
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
