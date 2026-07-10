"use client";

import { cn } from "@/lib/utils";
import { Check, X } from "lucide-react";
import { useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";

export type WizardStepDef = {
  id: string;
  label: string;
  description: string;
};

type WizardLayoutProps = {
  open: boolean;
  onClose: () => void;
  /** Fallback dialog label when ariaLabel is omitted. */
  title?: string;
  steps: readonly WizardStepDef[];
  currentStepId: string;
  children: ReactNode;
  footer: ReactNode;
  ariaLabel?: string;
  closeDisabled?: boolean;
};

function stepIndex(steps: readonly WizardStepDef[], id: string): number {
  return steps.findIndex((s) => s.id === id);
}

const SUBHEADER_ROW_CLASS = "flex h-9 shrink-0 items-center border-b border-border";

export function WizardLayout({
  open,
  onClose,
  title,
  steps,
  currentStepId,
  children,
  footer,
  ariaLabel,
  closeDisabled,
}: WizardLayoutProps) {
  const currentIdx = stepIndex(steps, currentStepId);
  const currentStep = steps[currentIdx];

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !closeDisabled) onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose, closeDisabled]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[300] flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="Close"
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
        onClick={closeDisabled ? undefined : onClose}
        disabled={closeDisabled}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel ?? title}
        className="relative flex max-h-[min(760px,calc(100vh-2rem))] w-full max-w-4xl flex-col overflow-hidden rounded-xl border border-border bg-raised shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          onClick={onClose}
          disabled={closeDisabled}
          className="absolute right-3 top-3 z-10 shrink-0 rounded-md p-1.5 text-fg-subtle transition-colors hover:bg-surface-2 hover:text-fg disabled:cursor-not-allowed disabled:opacity-50"
          aria-label="Close"
        >
          <X className="h-4 w-4" />
        </button>

        <div className="grid min-h-0 flex-1 sm:grid-cols-[264px_1fr]">
          {/* Left rail */}
          <aside className="hidden min-h-0 flex-col border-r border-border bg-surface sm:flex">
            <div className={cn(SUBHEADER_ROW_CLASS, "px-4")}>
              <p className="text-2xs text-fg-subtle">
                Step {currentIdx + 1} of {steps.length}
              </p>
            </div>
            <nav className="flex-1 overflow-y-auto p-3">
              <ol className="space-y-0.5">
                {steps.map((s, i) => {
                  const active = s.id === currentStepId;
                  const done = i < currentIdx;
                  return (
                    <li
                      key={s.id}
                      className={cn(
                        "wizard-step-item flex items-start gap-2.5 rounded-lg px-3 py-2.5 transition-colors duration-200",
                        active && "wizard-step-active bg-ok-green/[0.07]",
                      )}
                    >
                      <span
                        className={cn(
                          "wizard-step-indicator mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-2xs font-semibold transition-colors",
                          done
                            ? "bg-ok-green text-white"
                            : active
                              ? "bg-ok-green/15 text-ok-green ring-1 ring-ok-green/30"
                              : "bg-surface-2 text-fg-subtle",
                        )}
                      >
                        {done ? <Check className="h-3 w-3" strokeWidth={3} /> : i + 1}
                      </span>
                      <span className="min-w-0">
                        <span
                          className={cn(
                            "block text-sm font-medium transition-colors duration-200",
                            active ? "text-fg" : "text-fg-subtle",
                          )}
                        >
                          {s.label}
                        </span>
                        <span className="block text-2xs text-fg-faint">{s.description}</span>
                      </span>
                    </li>
                  );
                })}
              </ol>
            </nav>
          </aside>

          {/* Right column */}
          <div className="flex min-h-0 min-w-0 flex-col">
            <div className={cn(SUBHEADER_ROW_CLASS, "px-5 pr-12 sm:hidden")}>
              <p className="text-sm font-medium text-fg">
                {currentStep?.label}
                <span className="ml-1.5 text-2xs text-fg-faint">
                  {currentIdx + 1}/{steps.length}
                </span>
              </p>
            </div>
            <div className={cn(SUBHEADER_ROW_CLASS, "hidden px-6 sm:flex")} aria-hidden />

            <div className="flex-1 overflow-y-auto px-5 py-4 sm:px-6">{children}</div>

            {footer}
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}
