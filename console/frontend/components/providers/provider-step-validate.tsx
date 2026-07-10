"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Button } from "@/components/ui";
import type { CasePlatform } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  BadgeCheck,
  Loader2,
  RadioTower,
  XCircle,
  Zap,
} from "lucide-react";
import type { ProviderWizardData } from "./types";
import { awsAuthMethodLabel, azureAuthMethodLabel, gcpAuthMethodLabel, k8sAuthMethodLabel, m365AuthMethodLabel, platformLabel } from "./types";

export type ConnectionTestResult = {
  ok: boolean;
  account_id?: string;
  arn?: string;
  tenant_id?: string;
  principal?: string;
  project_id?: string;
  context?: string;
  cluster?: string;
  error?: string;
};

function SummaryRow({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <span className="text-fg-subtle">{label}</span>
      <span className="mono truncate text-right text-xs text-fg">{value}</span>
    </div>
  );
}

function IdentityRow({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div className="flex items-baseline justify-between gap-4">
      <span className="text-2xs font-semibold uppercase tracking-wide text-ok-green/80">{label}</span>
      <span className="mono truncate text-right text-xs text-fg">{value}</span>
    </div>
  );
}

/** The headline identity Ventra proved it can reach, per platform. */
function primaryIdentity(
  platform: string,
  r: ConnectionTestResult,
): { label: string; value: string } | null {
  if (r.principal) return { label: "Principal", value: r.principal };
  if (r.arn) return { label: "Caller ARN", value: r.arn };
  if (platform === "gcp" && r.project_id) return { label: "Project", value: r.project_id };
  if (platform === "kubernetes" && r.context) return { label: "Context", value: r.context };
  if ((platform === "azure" || platform === "m365") && r.tenant_id)
    return { label: "Tenant", value: r.tenant_id };
  if (r.account_id) return { label: "Account", value: r.account_id };
  return null;
}

export function ProviderStepValidate({
  data,
  testResult,
  testing,
  tested,
  onTest,
}: {
  data: ProviderWizardData;
  testResult: ConnectionTestResult | null;
  testing: boolean;
  tested: boolean;
  onTest: () => void;
}) {
  const platform = data.platform;
  const disabled = !platform;
  const identity = testResult?.ok ? primaryIdentity(platform, testResult) : null;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-semibold text-fg">Verify &amp; save</h2>
      </div>

      {/* Configuration summary */}
      <div className="rounded-xl border border-border bg-surface-2/40 p-4">
        <div className="flex items-center gap-3 border-b border-border pb-3">
          {platform && (
            <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-bg">
              <CloudProviderIcon cloud={platform as CasePlatform} />
            </span>
          )}
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-fg">
              {data.name || data.alias || (platform ? platformLabel(platform) : "Provider")}
            </p>
            <p className="text-xs text-fg-subtle">{platform ? platformLabel(platform) : "—"}</p>
          </div>
        </div>
        <div className="divide-y divide-border pt-1">
          {platform === "aws" && (
            <>
              <SummaryRow label="Auth method" value={awsAuthMethodLabel(data.auth_method)} />
              {data.auth_method === "assume_role" ? (
                <SummaryRow label="Role ARN" value={data.role_arn} />
              ) : (
                <SummaryRow label="Access Key ID" value={data.aws_access_key_id} />
              )}
              <SummaryRow label="Account ID" value={data.aws_account_id} />
            </>
          )}
          {platform === "gcp" && (
            <>
              <SummaryRow label="Auth method" value={gcpAuthMethodLabel(data.auth_method)} />
              <SummaryRow label="Project" value={data.project} />
              {data.auth_method === "service_account" && (
                <SummaryRow
                  label="Service account"
                  value={
                    data.gcp_service_account_json.trim()
                      ? (() => {
                          try {
                            return (
                              (JSON.parse(data.gcp_service_account_json) as { client_email?: string })
                                .client_email || "Key provided"
                            );
                          } catch {
                            return "Key provided";
                          }
                        })()
                      : "Saved key"
                  }
                />
              )}
            </>
          )}
          {platform === "azure" && (
            <>
              <SummaryRow label="Auth method" value={azureAuthMethodLabel(data.auth_method)} />
              <SummaryRow label="Tenant ID" value={data.azure_tenant_id} />
              <SummaryRow label="Client ID" value={data.azure_client_id} />
              <SummaryRow label="Subscription" value={data.subscription} />
            </>
          )}
          {platform === "m365" && (
            <>
              <SummaryRow label="Auth method" value={m365AuthMethodLabel(data.auth_method)} />
              <SummaryRow label="Domain ID" value={data.m365_domain} />
              <SummaryRow label="Tenant ID" value={data.azure_tenant_id} />
              <SummaryRow label="Client ID" value={data.azure_client_id} />
              {data.auth_method === "certificate" && (
                <SummaryRow
                  label="Certificate"
                  value={
                    data.azure_client_certificate_content.trim()
                      ? "Provided"
                      : "Saved certificate"
                  }
                />
              )}
            </>
          )}
          {platform === "kubernetes" && (
            <>
              <SummaryRow label="Auth method" value={k8sAuthMethodLabel(data.auth_method)} />
              <SummaryRow label="Kubernetes Context" value={data.k8s_context} />
              <SummaryRow
                label="Kubeconfig"
                value={data.kubeconfig_content.trim() ? "Provided" : "Saved on server"}
              />
            </>
          )}
        </div>
      </div>

      {/* Test action */}
      <Button
        variant="primary"
        icon={testing ? undefined : Zap}
        loading={testing}
        onClick={onTest}
        disabled={disabled}
        className="w-full justify-center sm:w-auto"
      >
        {testing ? "Testing connection…" : tested ? "Test again" : "Test connection"}
      </Button>

      {/* Scanning state */}
      {testing && (
        <div className="flex items-center gap-3 rounded-xl border border-border-strong/60 bg-surface-2/50 p-4">
          <RadioTower className="h-4 w-4 shrink-0 animate-pulse text-ok-green/80" />
          <p className="text-sm text-fg-subtle">
            Reaching {platform ? platformLabel(platform) : "provider"} with server-side credentials…
          </p>
          <Loader2 className="ml-auto h-4 w-4 animate-spin text-ok-green/80" />
        </div>
      )}

      {/* Verified identity */}
      {!testing && testResult?.ok && (
        <div className="overflow-hidden rounded-xl border border-ok-green/40 bg-ok-green/[0.07]">
          <div className="flex items-center gap-2.5 border-b border-ok-green/20 px-4 py-3">
            <BadgeCheck className="h-5 w-5 text-ok-green" />
            <div>
              <p className="text-sm font-semibold text-ok-green">Connection verified</p>
              {identity && (
                <p className="text-2xs text-fg-subtle">
                  Ventra authenticated as the identity below.
                </p>
              )}
            </div>
          </div>
          <div className="space-y-2 px-4 py-3">
            {identity && (
              <div className="rounded-lg border border-ok-green/25 bg-bg/40 px-3 py-2.5">
                <span className="block text-2xs font-semibold uppercase tracking-wide text-ok-green/80">
                  {identity.label}
                </span>
                <span className="mono mt-0.5 block break-all text-sm text-fg">{identity.value}</span>
              </div>
            )}
            <div className="space-y-1.5">
              {testResult.account_id !== identity?.value && (
                <IdentityRow label="Account" value={testResult.account_id} />
              )}
              {testResult.arn !== identity?.value && (
                <IdentityRow label="ARN" value={testResult.arn} />
              )}
              {testResult.project_id !== identity?.value && (
                <IdentityRow label="Project" value={testResult.project_id} />
              )}
              {testResult.tenant_id !== identity?.value && (
                <IdentityRow label="Tenant" value={testResult.tenant_id} />
              )}
              {testResult.context !== identity?.value && (
                <IdentityRow label="Context" value={testResult.context} />
              )}
              {testResult.cluster !== identity?.value && (
                <IdentityRow label="Cluster" value={testResult.cluster} />
              )}
            </div>
          </div>
        </div>
      )}

      {/* Failure */}
      {!testing && testResult && !testResult.ok && (
        <div className="overflow-hidden rounded-xl border border-bad-red/40 bg-bad-red/[0.06]">
          <div className="flex items-center gap-2.5 border-b border-bad-red/20 px-4 py-3">
            <XCircle className="h-5 w-5 text-bad-red" />
            <p className="text-sm font-semibold text-bad-red">Connection failed</p>
          </div>
          <div className="px-4 py-3 text-xs leading-relaxed text-fg-subtle">
            <p className="mono break-words text-fg">
              {testResult.error || "The provider rejected the server-side credentials."}
            </p>
            <p className="mt-2">
              Check the host credential set and the read-only permissions, then test again.
            </p>
          </div>
        </div>
      )}

      {/* Pre-test / save-anyway guidance */}
      {(!tested || (tested && !testResult?.ok)) && !testing && (
        <div className="flex gap-2.5 rounded-lg border border-warn-amber/30 bg-warn-amber/5 p-3 text-xs leading-relaxed text-fg-subtle">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warn-amber" />
          <p>
            {!tested
              ? "Test before saving to confirm credentials work on the Ventra server."
              : "You can still save without a passing test, but collection runs may fail until the host credentials are fixed."}
          </p>
        </div>
      )}
    </div>
  );
}
