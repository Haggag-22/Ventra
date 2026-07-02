"use client";

import { Button } from "@/components/ui";
import {
  GCP_LOG_BACKEND_IAM,
  GCP_LOG_BACKEND_OPTIONS,
  type GcpLogBackendMode,
} from "@/lib/gcp-log-backend";
import { X } from "lucide-react";

export function GcpLogBackendIamDialog({
  mode,
  open,
  onClose,
}: {
  mode: GcpLogBackendMode | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!open || !mode) return null;

  const label = GCP_LOG_BACKEND_OPTIONS.find((o) => o.mode === mode)?.label ?? mode;
  const actions = GCP_LOG_BACKEND_IAM[mode];

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4 animate-fade-in"
      onMouseDown={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 className="text-sm font-semibold text-fg">Required permissions — {label}</h3>
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="overflow-y-auto px-4 py-3">
          <ul className="space-y-1 rounded-md border border-border bg-surface-2 p-3">
            {actions.map((action) => (
              <li key={action} className="mono text-xs text-fg">
                {action}
              </li>
            ))}
          </ul>
        </div>

        <div className="border-t border-border px-4 py-3">
          <Button variant="secondary" className="w-full justify-center" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}
