"use client";

import { Input } from "@/components/ui";
import { cn } from "@/lib/utils";
import { AlertCircle } from "lucide-react";
import { useState } from "react";
import {
  validateAccountId,
  validateGuid,
} from "./provider-meta";
import type { ProviderWizardData } from "./types";
import { platformLabel } from "./types";

function Field({
  label,
  required,
  error,
  className,
  children,
}: {
  label: string;
  required?: boolean;
  error?: string | null;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <label className={cn("block space-y-1.5", className)}>
      <span className="flex items-center gap-1 text-xs font-medium text-fg-subtle">
        {label}
        {required && <span className="text-bad-red">*</span>}
      </span>
      {children}
      {error && (
        <span className="flex items-center gap-1 text-2xs text-bad-red">
          <AlertCircle className="h-3 w-3 shrink-0" />
          {error}
        </span>
      )}
    </label>
  );
}

export function ProviderStepDetails({
  data,
  onChange,
}: {
  data: ProviderWizardData;
  onChange: (patch: Partial<ProviderWizardData>) => void;
}) {
  const platform = data.platform;
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const markTouched = (key: string) => setTouched((t) => ({ ...t, [key]: true }));

  const accountErr = touched.aws_account_id ? validateAccountId(data.aws_account_id) : null;
  const subErr = touched.subscription
    ? validateGuid(data.subscription, "Subscription ID")
    : null;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-semibold text-fg">Name &amp; scope</h2>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Display name" required className="sm:col-span-2">
          <Input
            value={data.name}
            onChange={(e) => onChange({ name: e.target.value })}
            placeholder={`My ${platform ? platformLabel(platform) : "cloud"} account`}
            autoFocus
          />
        </Field>

        <Field
          label={platform === "azure" || platform === "m365" || platform === "kubernetes" ? "Provider alias" : "Alias"}
          className="sm:col-span-2"
        >
          <Input
            value={data.alias}
            onChange={(e) => onChange({ alias: e.target.value })}
            placeholder={
              platform === "azure" || platform === "m365" || platform === "kubernetes"
                ? "Enter the provider alias"
                : "Production"
            }
          />
        </Field>

        {platform === "aws" && (
          <Field label="Account ID" className="sm:col-span-2" error={accountErr}>
            <Input
              value={data.aws_account_id}
              onChange={(e) => onChange({ aws_account_id: e.target.value })}
              onBlur={() => markTouched("aws_account_id")}
              placeholder="123456789012"
              inputMode="numeric"
              className={cn("mono", accountErr && "border-bad-red/60 focus:border-bad-red")}
            />
          </Field>
        )}

        {platform === "gcp" && (
          <Field label="Project ID" required className="sm:col-span-2">
            <Input
              value={data.project}
              onChange={(e) => onChange({ project: e.target.value })}
              placeholder="my-gcp-project"
              className="mono"
            />
          </Field>
        )}

        {platform === "m365" && (
          <Field label="Domain ID" required className="sm:col-span-2">
            <Input
              value={data.m365_domain}
              onChange={(e) => onChange({ m365_domain: e.target.value })}
              placeholder="e.g. your-domain.onmicrosoft.com"
              className="mono"
            />
          </Field>
        )}

        {platform === "azure" && (
          <Field
            label="Subscription ID"
            required
            className="sm:col-span-2"
            error={subErr}
          >
            <Input
              value={data.subscription}
              onChange={(e) => onChange({ subscription: e.target.value })}
              onBlur={() => markTouched("subscription")}
              placeholder="fc94207a-d396-4a14-a7fd-12ab34cd56ef"
              className={cn("mono", subErr && "border-bad-red/60 focus:border-bad-red")}
            />
          </Field>
        )}

        {platform === "kubernetes" && (
          <Field label="Kubernetes Context" required className="sm:col-span-2">
            <Input
              value={data.k8s_context}
              onChange={(e) => onChange({ k8s_context: e.target.value })}
              placeholder="e.g. my-cluster-context"
              className="mono"
            />
          </Field>
        )}
      </div>
    </div>
  );
}
