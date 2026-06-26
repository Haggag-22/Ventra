"use client";

import { Button } from "@/components/ui";
import { CLOUD_LABELS, type Cloud } from "@/lib/catalog";
import { List, X } from "lucide-react";
import { useEffect } from "react";

type Props = {
  open: boolean;
  onClose: () => void;
  cloud: Cloud;
  actions: string[];
  actionCount: number;
  implicitCount: number;
};

export function IamActionsDialog({
  open,
  onClose,
  cloud,
  actions,
  actionCount,
  implicitCount,
}: Props) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4 animate-fade-in"
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
            IAM actions — {CLOUD_LABELS[cloud]}
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
            <p className="text-sm text-fg-subtle">No IAM actions in this preview.</p>
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
    </div>
  );
}
