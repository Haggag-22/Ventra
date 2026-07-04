"use client";

import { Input } from "@/components/ui";
import { PROVIDER_IAM_POLICIES, type DocProvider } from "@/lib/docs-routes";
import { docsProviderHref } from "@/lib/docs-routes";
import { ExternalLink, Server, Shield } from "lucide-react";
import Link from "next/link";
import type { ProviderWizardData } from "./types";
import { platformLabel } from "./types";

function IamPolicyLinks({ platform }: { platform: string }) {
  const key = platform.toLowerCase();
  const docKey = key === "m365" ? "azure" : key;
  const policies = PROVIDER_IAM_POLICIES[docKey as DocProvider];

  if (!policies?.length) return null;

  return (
    <div className="rounded-lg border border-border bg-surface-2 p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-fg">
        <Shield className="h-4 w-4 text-accent" />
        Required IAM permissions
      </div>
      <p className="mt-1 text-xs text-fg-subtle leading-relaxed">
        Grant read-only access on the provider using Ventra&apos;s collector policy templates.
      </p>
      <ul className="mt-3 space-y-1.5">
        {policies.map((p) => (
          <li key={p.path}>
            <a
              href={`/${p.path}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-accent hover:underline"
            >
              {p.label}
              <ExternalLink className="h-3 w-3" />
            </a>
          </li>
        ))}
        <li>
          <Link
            href={docsProviderHref(docKey)}
            className="inline-flex items-center gap-1.5 text-xs text-fg-subtle hover:text-fg"
          >
            Provider documentation
            <ExternalLink className="h-3 w-3" />
          </Link>
        </li>
      </ul>
    </div>
  );
}

export function ProviderStepAuth({
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
        <h2 className="text-base font-semibold text-fg">Authenticate</h2>
        <p className="mt-1 text-sm text-fg-subtle">
          Credentials live on the Ventra server host. Configure named profiles, IAM roles, or
          service principals on the machine running Ventra — no secrets are entered in this
          browser session.
        </p>
      </div>

      <div className="flex gap-3 rounded-lg border border-accent/25 bg-accent/5 p-4">
        <Server className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
        <div className="text-sm leading-relaxed text-fg-subtle">
          <p className="font-medium text-fg">Server-side credentials</p>
          <p className="mt-1">
            Ventra uses ambient credentials from the host (AWS profiles, GCP ADC, Azure
            DefaultAzureCredential). The fields below identify which credential set or scope to use
            — they are not secret values.
          </p>
        </div>
      </div>

      {platform === "aws" && data.auth_method === "profile" && (
        <label className="block space-y-1.5">
          <span className="text-xs font-medium text-fg-subtle">AWS profile name</span>
          <Input
            value={data.profile_name}
            onChange={(e) => onChange({ profile_name: e.target.value })}
            placeholder="default (leave empty for ambient credentials)"
          />
          <p className="text-xs text-fg-subtle">
            Named profile from <code className="mono text-2xs">~/.aws/credentials</code> on the
            Ventra server.
          </p>
        </label>
      )}

      {platform === "aws" && data.auth_method === "role" && (
        <label className="block space-y-1.5">
          <span className="text-xs font-medium text-fg-subtle">Role ARN</span>
          <Input
            value={data.role_arn}
            onChange={(e) => onChange({ role_arn: e.target.value })}
            placeholder="arn:aws:iam::123456789012:role/VentraCollector"
            className="mono"
          />
          <p className="text-xs text-fg-subtle">
            Cross-account role Ventra assumes using the server&apos;s base credentials.
          </p>
        </label>
      )}

      {platform === "gcp" && (
        <p className="text-sm text-fg-subtle">
          Ensure Application Default Credentials are configured on the Ventra server for project{" "}
          <span className="mono text-xs text-fg">{data.project || "(not set)"}</span>. Use{" "}
          <code className="mono text-2xs">gcloud auth application-default login</code> or a service
          account key referenced by <code className="mono text-2xs">GOOGLE_APPLICATION_CREDENTIALS</code>.
        </p>
      )}

      {(platform === "azure" || platform === "m365") && (
        <p className="text-sm text-fg-subtle">
          Configure the app registration on the Ventra server with client secret or certificate.
          Tenant <span className="mono text-xs text-fg">{data.azure_tenant_id || "—"}</span>, client{" "}
          <span className="mono text-xs text-fg">{data.azure_client_id || "—"}</span>
          {platform === "azure" && (
            <>
              , subscription{" "}
              <span className="mono text-xs text-fg">{data.subscription || "—"}</span>
            </>
          )}
          .
        </p>
      )}

      {platform && platform !== "kubernetes" && <IamPolicyLinks platform={platform} />}

      {platform === "kubernetes" && (
        <p className="text-sm text-fg-subtle">Kubernetes authentication is not yet available.</p>
      )}

      {!platform && (
        <p className="text-sm text-fg-subtle">
          Select a provider in step 1 to configure authentication for{" "}
          {platformLabel(platform || "your cloud")}.
        </p>
      )}
    </div>
  );
}
