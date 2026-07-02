"use client";

import { Button } from "@/components/ui";
import {
  GCP_LOG_EXPORT_SETUP,
  type GcpLogExportSetupKind,
} from "@/lib/gcp-log-export-setup";
import { X } from "lucide-react";

export function GcpLogExportSetupDialog({
  kind,
  open,
  onClose,
}: {
  kind: GcpLogExportSetupKind | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!open || !kind) return null;

  const guide = GCP_LOG_EXPORT_SETUP[kind];

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
          <h3 className="text-sm font-semibold text-fg">{guide.title}</h3>
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 overflow-y-auto px-4 py-3 text-sm text-fg">
          <p className="text-xs text-fg-subtle">{guide.intro}</p>
          <ol className="list-decimal space-y-3 pl-4 text-xs">
            {guide.steps.map((step) => (
              <li key={step.title}>
                <span className="font-medium text-fg">{step.title}</span>
                <p className="mt-0.5 text-fg-subtle">{step.body}</p>
              </li>
            ))}
          </ol>
          <div>
            <p className="mb-1.5 text-2xs font-medium uppercase tracking-wide text-fg-subtle">
              Example (gcloud)
            </p>
            <pre className="overflow-x-auto rounded-md border border-border bg-surface-2 p-3 text-2xs leading-relaxed text-fg">
              {guide.commands}
            </pre>
          </div>
          <p className="text-xs text-fg-subtle">{guide.footnote}</p>
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
