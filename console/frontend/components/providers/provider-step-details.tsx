"use client";

import { Input } from "@/components/ui";
import { cn } from "@/lib/utils";
import { KeyRound, UserCircle } from "lucide-react";
import type { ProviderAuthMethod, ProviderWizardData } from "./types";
import { platformLabel } from "./types";

function AuthMethodCard({
  selected,
  title,
  description,
  icon: Icon,
  onClick,
}: {
  selected: boolean;
  title: string;
  description: string;
  icon: typeof UserCircle;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex items-start gap-3 rounded-lg border p-4 text-left transition-colors",
        selected
          ? "border-accent/60 bg-accent/10 ring-1 ring-accent/30"
          : "border-border bg-surface hover:border-border-strong hover:bg-surface-2",
      )}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle" />
      <span>
        <span className="block text-sm font-medium text-fg">{title}</span>
        <span className="mt-0.5 block text-xs text-fg-subtle leading-relaxed">{description}</span>
      </span>
    </button>
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

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-semibold text-fg">Provider details</h2>
        <p className="mt-1 text-sm text-fg-subtle">
          Configure how this {platform ? platformLabel(platform) : "cloud"} provider appears in
          Ventra and which scope to target.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block space-y-1.5 sm:col-span-2">
          <span className="text-xs font-medium text-fg-subtle">Display name</span>
          <Input
            value={data.name}
            onChange={(e) => onChange({ name: e.target.value })}
            placeholder={`My ${platform ? platformLabel(platform) : "cloud"} account`}
          />
        </label>

        <label className="block space-y-1.5 sm:col-span-2">
          <span className="text-xs font-medium text-fg-subtle">Alias (optional)</span>
          <Input
            value={data.alias}
            onChange={(e) => onChange({ alias: e.target.value })}
            placeholder="Production, EU tenant, etc."
          />
        </label>

        {platform === "aws" && (
          <>
            <label className="block space-y-1.5">
              <span className="text-xs font-medium text-fg-subtle">Account ID (optional)</span>
              <Input
                value={data.aws_account_id}
                onChange={(e) => onChange({ aws_account_id: e.target.value })}
                placeholder="123456789012"
                className="mono"
              />
            </label>
            <div className="sm:col-span-2">
              <span className="text-xs font-medium text-fg-subtle">Authentication method</span>
              <div className="mt-2 grid gap-3 sm:grid-cols-2">
                <AuthMethodCard
                  selected={data.auth_method === "profile"}
                  title="Ambient / named profile"
                  description="Use AWS credentials or a named profile on the Ventra server host."
                  icon={UserCircle}
                  onClick={() => onChange({ auth_method: "profile" as ProviderAuthMethod })}
                />
                <AuthMethodCard
                  selected={data.auth_method === "role"}
                  title="Assume IAM role"
                  description="Ventra assumes a cross-account IAM role using server-side credentials."
                  icon={KeyRound}
                  onClick={() => onChange({ auth_method: "role" as ProviderAuthMethod })}
                />
              </div>
            </div>
          </>
        )}

        {platform === "gcp" && (
          <label className="block space-y-1.5 sm:col-span-2">
            <span className="text-xs font-medium text-fg-subtle">GCP project ID</span>
            <Input
              value={data.project}
              onChange={(e) => onChange({ project: e.target.value })}
              placeholder="my-gcp-project"
              className="mono"
            />
          </label>
        )}

        {(platform === "azure" || platform === "m365") && (
          <>
            <label className="block space-y-1.5">
              <span className="text-xs font-medium text-fg-subtle">Tenant ID</span>
              <Input
                value={data.azure_tenant_id}
                onChange={(e) => onChange({ azure_tenant_id: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="mono"
              />
            </label>
            <label className="block space-y-1.5">
              <span className="text-xs font-medium text-fg-subtle">Client ID (app registration)</span>
              <Input
                value={data.azure_client_id}
                onChange={(e) => onChange({ azure_client_id: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="mono"
              />
            </label>
            {platform === "azure" && (
              <label className="block space-y-1.5 sm:col-span-2">
                <span className="text-xs font-medium text-fg-subtle">Subscription ID</span>
                <Input
                  value={data.subscription}
                  onChange={(e) => onChange({ subscription: e.target.value })}
                  placeholder="00000000-0000-0000-0000-000000000000"
                  className="mono"
                />
              </label>
            )}
          </>
        )}

        {platform === "kubernetes" && (
          <div className="sm:col-span-2 rounded-lg border border-border bg-surface-2 p-4">
            <p className="text-sm font-medium text-fg">Kubernetes support is coming soon</p>
            <p className="mt-1 text-sm text-fg-subtle">
              Cluster-based collection will be available in a future release. Choose AWS, GCP,
              Azure, or Microsoft 365 for now.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
