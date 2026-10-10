"use client";

import {
  AZURE_LOG_BACKEND_OPTIONS,
  type AzureLogBackendFormState,
} from "@/lib/azure-log-backend";
import { cn } from "@/lib/utils";
import { AlertTriangle } from "lucide-react";

type Props = {
  form: AzureLogBackendFormState;
  onChange: (next: AzureLogBackendFormState) => void;
  required?: boolean;
};

export function AzureLogBackendFields({ form, onChange, required = false }: Props) {
  return (
    <div className="mb-5 rounded-lg border border-border bg-surface p-4">
      <div className="mb-3">
        <h3 className="text-base font-semibold text-fg">
          Azure Activity Log source
          {required && <span className="ml-1 text-bad-red">*</span>}
        </h3>
        <p className="mt-1 text-sm text-fg">
          Choose where Activity Logs are read from. Other Azure collectors still discover their own
          storage accounts.
        </p>
      </div>

      <div className="space-y-2">
        {AZURE_LOG_BACKEND_OPTIONS.map((opt) => {
          const selected = form.mode === opt.mode;
          return (
            <label
              key={opt.mode}
              className={cn(
                "flex cursor-pointer gap-3 rounded-md border border-border bg-surface-2 px-3 py-3",
                selected && "border-l-2 border-l-[#0078D4] pl-[10px]",
              )}
            >
              <input
                type="radio"
                name="azure_log_backend"
                checked={selected}
                onChange={() => onChange({ mode: opt.mode })}
                className="mt-1 shrink-0"
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-semibold text-fg">{opt.label}</span>
                <span className="mt-0.5 block text-xs leading-relaxed text-fg">{opt.summary}</span>
                {selected && opt.warning && (
                  <span className="mt-2 flex items-start gap-1.5 text-xs text-warn-amber">
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    {opt.warning}
                  </span>
                )}
              </span>
            </label>
          );
        })}
      </div>
    </div>
  );
}
