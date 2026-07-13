"use client";

import { GcpLogBackendIamDialog } from "@/components/gcp-log-backend-iam-dialog";
import { GcpLogExportSetupDialog } from "@/components/gcp-log-export-setup-dialog";
import { Button, Input } from "@/components/ui";
import {
  GCP_LOG_BACKEND_ACCENT_CLASS,
  GCP_LOG_BACKEND_BUTTON_CLASS,
  GCP_LOG_BACKEND_OPTIONS,
  type GcpLogBackendFormState,
  type GcpLogBackendMode,
} from "@/lib/gcp-log-backend";
import type { GcpLogExportSetupKind } from "@/lib/gcp-log-export-setup";
import { cn } from "@/lib/utils";
import { AlertTriangle, BookOpen, ShieldCheck } from "lucide-react";
import { useState } from "react";

type Props = {
  form: GcpLogBackendFormState;
  onChange: (next: GcpLogBackendFormState) => void;
  required: boolean;
};

export function GcpLogBackendFields({ form, onChange, required }: Props) {
  const set = (patch: Partial<GcpLogBackendFormState>) => onChange({ ...form, ...patch });
  const [setupDialog, setSetupDialog] = useState<GcpLogExportSetupKind | null>(null);
  const [iamDialog, setIamDialog] = useState<GcpLogBackendMode | null>(null);

  return (
    <>
      <div className="mb-5 rounded-lg border border-border bg-surface p-4">
        <div className="mb-3">
          <h3 className="text-base font-semibold text-fg">
            GCP Log Collection Strategy
            {required && <span className="ml-1 text-bad-red">*</span>}
          </h3>
          <p className="mt-1 text-sm text-fg">
            Required for log collectors in this kit. Client configures Export or Archive before
            collection.
          </p>
        </div>

        <div className="space-y-2">
          {GCP_LOG_BACKEND_OPTIONS.map((opt) => {
            const selected = form.mode === opt.mode;
            return (
              <div
                key={opt.mode}
                className={cn(
                  "rounded-md border border-border bg-surface-2",
                  selected && cn("border-l-2 pl-[2px]", GCP_LOG_BACKEND_ACCENT_CLASS[opt.mode]),
                )}
              >
                <div className="flex items-start gap-3 px-3 py-3">
                  <label className="flex min-w-0 flex-1 cursor-pointer gap-3">
                    <input
                      type="radio"
                      name="gcp_log_backend"
                      checked={selected}
                      onChange={() => set({ mode: opt.mode })}
                      className="mt-1 shrink-0"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-semibold text-fg">{opt.label}</span>
                      <span className="mt-0.5 block text-xs leading-relaxed text-fg">
                        {opt.summary}
                      </span>
                      {selected && opt.warning && (
                        <span className="mt-2 flex items-start gap-1.5 text-xs text-warn-amber">
                          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                          {opt.warning}
                        </span>
                      )}
                    </span>
                  </label>

                  <div className="flex shrink-0 flex-col items-end gap-2">
                    {opt.mode === "gcs" && (
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        icon={BookOpen}
                        className={GCP_LOG_BACKEND_BUTTON_CLASS}
                        onClick={() => setSetupDialog("gcs")}
                      >
                        How to create bucket
                      </Button>
                    )}
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      icon={ShieldCheck}
                      className={GCP_LOG_BACKEND_BUTTON_CLASS}
                      onClick={() => setIamDialog(opt.mode)}
                    >
                      Required permissions
                    </Button>
                  </div>
                </div>

                {selected && opt.mode === "gcs" && (
                  <div className="space-y-2 border-t border-border/50 px-3 pb-3 pt-3">
                    <label className="block space-y-1.5">
                      <span className="text-sm font-medium text-fg">GCS bucket</span>
                      <Input
                        value={form.gcsBucket}
                        onChange={(e) => set({ gcsBucket: e.target.value })}
                        placeholder="gs://company-log-archive"
                        className="mono text-xs"
                      />
                    </label>
                    <label className="block space-y-1.5">
                      <span className="text-sm font-medium text-fg">Object prefix (optional)</span>
                      <Input
                        value={form.gcsPrefix}
                        onChange={(e) => set({ gcsPrefix: e.target.value })}
                        placeholder="2026/06/"
                        className="mono text-xs"
                      />
                    </label>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <GcpLogExportSetupDialog
        kind={setupDialog}
        open={setupDialog !== null}
        onClose={() => setSetupDialog(null)}
      />
      <GcpLogBackendIamDialog
        mode={iamDialog}
        open={iamDialog !== null}
        onClose={() => setIamDialog(null)}
      />
    </>
  );
}
