"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Badge, Button } from "@/components/ui";
import type { CasePlatform } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle2, XCircle, Zap } from "lucide-react";
import type { ProviderWizardData } from "./types";
import { platformLabel } from "./types";

export type ConnectionTestResult = {
  ok: boolean;
  account_id?: string;
  arn?: string;
  tenant_id?: string;
  principal?: string;
  project_id?: string;
  error?: string;
};

function SummaryRow({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <div className="flex justify-between gap-4 py-2 text-sm">
      <span className="text-fg-subtle">{label}</span>
      <span className="mono text-right text-xs text-fg">{value}</span>
    </div>
  );
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

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-semibold text-fg">Validate connection</h2>
        <p className="mt-1 text-sm text-fg-subtle">
          Review your configuration and test connectivity before saving. A successful test confirms
          Ventra can reach the provider using server-side credentials.
        </p>
      </div>

      <div className="rounded-lg border border-border bg-surface-2 p-4">
        <div className="flex items-center gap-3 border-b border-border pb-3">
          {platform && <CloudProviderIcon cloud={platform as CasePlatform} />}
          <div>
            <p className="text-sm font-semibold text-fg">
              {data.name || data.alias || (platform ? platformLabel(platform) : "Provider")}
            </p>
            {data.alias && data.name && (
              <p className="text-xs text-fg-subtle">{data.alias}</p>
            )}
            <p className="text-xs text-fg-subtle">{platform ? platformLabel(platform) : "—"}</p>
          </div>
        </div>

        <div className="divide-y divide-border">
          {platform === "aws" && (
            <>
              <SummaryRow
                label="Auth method"
                value={data.auth_method === "role" ? "Assume IAM role" : "Named profile"}
              />
              <SummaryRow
                label={data.auth_method === "role" ? "Role ARN" : "Profile"}
                value={data.auth_method === "role" ? data.role_arn : data.profile_name || "default"}
              />
              <SummaryRow label="Account ID" value={data.aws_account_id} />
            </>
          )}
          {platform === "gcp" && <SummaryRow label="Project" value={data.project} />}
          {(platform === "azure" || platform === "m365") && (
            <>
              <SummaryRow label="Tenant ID" value={data.azure_tenant_id} />
              <SummaryRow label="Client ID" value={data.azure_client_id} />
              {platform === "azure" && (
                <SummaryRow label="Subscription" value={data.subscription} />
              )}
            </>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant="secondary"
          icon={Zap}
          loading={testing}
          onClick={onTest}
          disabled={!platform || platform === "kubernetes"}
        >
          Test connection
        </Button>
        {tested && !testing && (
          <Badge
            className={cn(
              testResult?.ok
                ? "border-ok-green/40 bg-ok-green/10 text-ok-green"
                : "border-bad-red/40 bg-bad-red/10 text-bad-red",
            )}
          >
            {testResult?.ok ? (
              <CheckCircle2 className="h-3 w-3" />
            ) : (
              <XCircle className="h-3 w-3" />
            )}
            {testResult?.ok ? "Connection successful" : "Connection failed"}
          </Badge>
        )}
      </div>

      {testResult?.ok && (
        <div className="rounded-lg border border-ok-green/30 bg-ok-green/5 p-4 text-sm">
          <p className="font-medium text-ok-green">Connected successfully</p>
          <ul className="mt-2 space-y-1 text-xs text-fg-subtle">
            {testResult.account_id && (
              <li>
                Account: <span className="mono text-fg">{testResult.account_id}</span>
              </li>
            )}
            {testResult.arn && (
              <li>
                ARN: <span className="mono text-fg">{testResult.arn}</span>
              </li>
            )}
            {testResult.tenant_id && (
              <li>
                Tenant: <span className="mono text-fg">{testResult.tenant_id}</span>
              </li>
            )}
            {testResult.project_id && (
              <li>
                Project: <span className="mono text-fg">{testResult.project_id}</span>
              </li>
            )}
            {testResult.principal && (
              <li>
                Principal: <span className="mono text-fg">{testResult.principal}</span>
              </li>
            )}
          </ul>
        </div>
      )}

      {testResult && !testResult.ok && (
        <div className="rounded-lg border border-bad-red/30 bg-bad-red/5 p-4 text-sm text-bad-red">
          {testResult.error || "Connection test failed. Check server-side credentials."}
        </div>
      )}

      {(!tested || (tested && !testResult?.ok)) && (
        <div className="flex gap-2 rounded-lg border border-warn-amber/30 bg-warn-amber/5 p-3 text-xs text-fg-subtle">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warn-amber" />
          <p>
            {!tested
              ? "Test the connection before saving to confirm credentials work on the Ventra server."
              : "You can still save this provider without a successful test, but collection runs may fail until credentials are fixed on the Ventra server."}
          </p>
        </div>
      )}
    </div>
  );
}
