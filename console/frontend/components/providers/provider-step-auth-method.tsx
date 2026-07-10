"use client";

import { cn } from "@/lib/utils";
import type { ProviderWizardData } from "./types";

const AUTH_OPTION_CARD = (selected: boolean) =>
  cn("provider-auth-option-card", selected && "is-selected");

function AuthOptionCard({
  name,
  checked,
  onChange,
  title,
}: {
  name: string;
  checked: boolean;
  onChange: () => void;
  title: string;
}) {
  return (
    <label className={AUTH_OPTION_CARD(checked)}>
      <input
        type="radio"
        name={name}
        checked={checked}
        onChange={onChange}
        className="mt-0.5 shrink-0 accent-ok-green"
      />
      <span className="min-w-0 flex-1 text-sm font-medium text-fg">{title}</span>
    </label>
  );
}

export function ProviderStepAuthMethod({
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
        <h2 className="text-base font-semibold text-fg">Authentication method</h2>
      </div>

      {platform === "aws" && (
        <div className="space-y-2">
          <AuthOptionCard
            name="aws_auth_method"
            checked={data.auth_method === "assume_role"}
            onChange={() => onChange({ auth_method: "assume_role" })}
            title="Connect assuming IAM Role"
          />
          <AuthOptionCard
            name="aws_auth_method"
            checked={data.auth_method === "credentials"}
            onChange={() => onChange({ auth_method: "credentials" })}
            title="Connect via Credentials"
          />
        </div>
      )}

      {platform === "gcp" && (
        <div className="space-y-2">
          <AuthOptionCard
            name="gcp_auth_method"
            checked={data.auth_method === "service_account"}
            onChange={() => onChange({ auth_method: "service_account" })}
            title="Connect via Service Account Key"
          />
          <AuthOptionCard
            name="gcp_auth_method"
            checked={data.auth_method === "adc"}
            onChange={() => onChange({ auth_method: "adc" })}
            title="Connect via Application Default Credentials"
          />
        </div>
      )}

      {platform === "m365" && (
        <div className="space-y-2">
          <AuthOptionCard
            name="m365_auth_method"
            checked={data.auth_method === "client_secret"}
            onChange={() => onChange({ auth_method: "client_secret" })}
            title="App Client Secret Credentials"
          />
          <AuthOptionCard
            name="m365_auth_method"
            checked={data.auth_method === "certificate"}
            onChange={() => onChange({ auth_method: "certificate" })}
            title="App Certificate Credentials"
          />
        </div>
      )}

      {platform === "azure" && (
        <div className="space-y-2">
          <AuthOptionCard
            name="azure_auth_method"
            checked={data.auth_method === "service_principal"}
            onChange={() => onChange({ auth_method: "service_principal" })}
            title="Connect via Credentials"
          />
        </div>
      )}

      {platform === "kubernetes" && (
        <div className="space-y-2">
          <AuthOptionCard
            name="k8s_auth_method"
            checked={data.auth_method === "kubeconfig"}
            onChange={() => onChange({ auth_method: "kubeconfig" })}
            title="Connect via Credentials"
          />
        </div>
      )}

      {!platform && (
        <p className="text-sm text-fg-subtle">Select a provider in step 1 to continue.</p>
      )}
    </div>
  );
}
