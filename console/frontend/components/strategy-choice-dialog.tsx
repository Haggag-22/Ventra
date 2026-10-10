"use client";

import { Button } from "@/components/ui";
import { X } from "lucide-react";
import type { ReactNode } from "react";

export function StrategyChoiceDialog({
  open,
  onClose,
  children,
}: {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4 animate-fade-in"
      onMouseDown={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex justify-end border-b border-border px-3 py-2">
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="overflow-y-auto px-4 py-4">{children}</div>
        <div className="border-t border-border px-4 py-3">
          <Button variant="primary" className="w-full justify-center" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    </div>
  );
}
