"use client";

import { DeploymentTemplateLinks } from "@/components/deployment-template-links";
import { Input } from "@/components/ui";
import {
  PROVIDER_IAM_POLICIES,
  docsSectionHref,
  isDocProvider,
  type DocProvider,
} from "@/lib/docs-routes";
import { authWizardTemplates, deploymentTemplatesForProvider } from "@/lib/deployment-templates";
import { cn } from "@/lib/utils";
import type { ProviderWizardData } from "./types";
import { ExternalLink, Eye, EyeOff, Shield, Upload, FileJson } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { AwsPermissionScope } from "./aws-permission-scope";
import { AzurePermissionScope } from "./azure-permission-scope";
import { GcpPermissionScope } from "./gcp-permission-scope";
import { M365PermissionScope } from "./m365-permission-scope";
import { KubernetesPermissionScope } from "./kubernetes-permission-scope";
import {
  validateAccessKeyId,
  validateGcpServiceAccountJson,
  validateGuid,
  validateKubeconfigContext,
  validateKubeconfigYaml,
  validateRoleArn,
} from "./provider-meta";

const CREDENTIAL_INPUT_CLASS = "acquire-kit-input";

const LARGE_PASTE_TEXTAREA_CLASS = cn(
  "w-full min-h-[240px] !h-auto resize-y rounded-lg border border-border bg-bg px-3 py-2 font-mono text-xs text-fg placeholder:text-fg-faint focus:border-border-strong focus:outline-none",
  CREDENTIAL_INPUT_CLASS,
);

function IamPolicyLinks({ platform }: { platform: string }) {
  const key = platform.toLowerCase();
  if (!isDocProvider(key)) return null;
  const docKey = key as DocProvider;
  const policies = PROVIDER_IAM_POLICIES[docKey];
  const templates = deploymentTemplatesForProvider(docKey);
  const iacTemplates = authWizardTemplates(docKey);

  if (!policies?.length && !iacTemplates.length) return null;

  return (
    <div className="space-y-4">
      {iacTemplates.length > 0 && (
        <DeploymentTemplateLinks templates={templates} title="Deploy read-only access" />
      )}

      {policies?.length ? (
        <div className="rounded-lg border border-border bg-surface-2/40 p-4">
          <div className="flex items-center gap-2 text-sm font-medium text-fg">
            <Shield className="h-4 w-4 text-ok-green" />
            Required read-only permissions
          </div>
          <ul className="mt-3 flex flex-wrap gap-2">
            {policies.map((p) => (
              <li key={p.path}>
                <a
                  href={p.publicPath}
                  download
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-fg-subtle transition-colors hover:border-ok-green/30 hover:bg-ok-green/5 hover:text-ok-green"
                >
                  {p.label}
                  <ExternalLink className="h-3 w-3" />
                </a>
              </li>
            ))}
            <li>
              <Link
                href={docsSectionHref(docKey, "authentication")}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-fg-subtle transition-colors hover:border-border-strong hover:text-fg"
              >
                Provider docs
                <ExternalLink className="h-3 w-3" />
              </Link>
            </li>
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function Field({
  label,
  required,
  error,
  children,
}: {
  label: string;
  required?: boolean;
  error?: string | null;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="flex items-center gap-1 text-xs font-medium text-fg-subtle">
        {label}
        {required && <span className="text-bad-red">*</span>}
      </span>
      {children}
      {error && <span className="block text-2xs text-bad-red">{error}</span>}
    </label>
  );
}

function SecretField({
  label,
  value,
  onChange,
  required,
  editing,
  placeholder,
  className,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
  editing?: boolean;
  placeholder?: string;
  className?: string;
}) {
  const [visible, setVisible] = useState(false);

  return (
    <Field label={label} required={required}>
      <div className="relative">
        <Input
          type={visible ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete="new-password"
          className={cn("mono pr-10", CREDENTIAL_INPUT_CLASS, className)}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-fg-subtle transition-colors hover:text-fg"
          aria-label={visible ? "Hide secret" : "Show secret"}
        >
          {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    </Field>
  );
}

function GcpServiceAccountKeyField({
  value,
  onChange,
  editing,
  error,
  onBlur,
}: {
  value: string;
  onChange: (json: string) => void;
  editing: boolean;
  error: string | null;
  onBlur: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);

  const loadFile = (file: File | null) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result ?? "");
      onChange(text);
      setFileName(file.name);
    };
    reader.readAsText(file);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) loadFile(file);
  };

  return (
    <Field label="Service account key (JSON)" required={!editing} error={error}>
      <div
        role="button"
        tabIndex={0}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        className={cn(
          "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-5 text-center transition-colors",
          dragOver
            ? "border-ok-green/60 bg-ok-green/5"
            : "border-border bg-surface-2/40 hover:border-border-strong",
          error && "border-bad-red/60",
        )}
      >
        {fileName || (editing && !value.trim()) ? (
          <>
            <FileJson className="h-5 w-5 text-ok-green" />
            <span className="text-xs font-medium text-fg">
              {fileName || (editing ? "Saved key on file" : "Key loaded")}
            </span>
            <span className="text-2xs text-fg-faint">Click or drop to replace</span>
          </>
        ) : (
          <>
            <Upload className="h-5 w-5 text-fg-subtle" />
            <span className="text-xs text-fg">Drop JSON key here or click to browse</span>
          </>
        )}
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".json,application/json"
        className="hidden"
        onChange={(e) => loadFile(e.target.files?.[0] ?? null)}
      />
      <textarea
        value={value}
        onChange={(e) => {
          setFileName(null);
          onChange(e.target.value);
        }}
        onBlur={onBlur}
        rows={12}
        spellCheck={false}
        placeholder={
          editing
            ? "Paste new JSON to replace the saved key, or leave blank"
            : '{"type": "service_account", "project_id": "...", ...}'
        }
        className={cn(
          "mt-2",
          LARGE_PASTE_TEXTAREA_CLASS,
          error && "border-bad-red/60 focus:border-bad-red",
        )}
      />
    </Field>
  );
}

export function ProviderStepAuth({
  data,
  onChange,
  editing = false,
}: {
  data: ProviderWizardData;
  onChange: (patch: Partial<ProviderWizardData>) => void;
  editing?: boolean;
}) {
  const platform = data.platform;
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const markTouched = (key: string) => setTouched((t) => ({ ...t, [key]: true }));

  const accessKeyErr = touched.aws_access_key_id
    ? validateAccessKeyId(data.aws_access_key_id)
    : null;
  const roleArnErr = touched.role_arn ? validateRoleArn(data.role_arn) : null;
  const gcpKeyErr =
    data.auth_method === "service_account" && touched.gcp_service_account_json
      ? validateGcpServiceAccountJson(data.gcp_service_account_json)
      : null;
  const tenantErr = touched.azure_tenant_id
    ? validateGuid(data.azure_tenant_id, "Tenant ID")
    : null;
  const clientErr = touched.azure_client_id
    ? validateGuid(data.azure_client_id, "Client ID")
    : null;
  const kubeconfigErr =
    data.auth_method === "kubeconfig" && touched.kubeconfig_content
      ? validateKubeconfigYaml(data.kubeconfig_content) ||
        validateKubeconfigContext(data.kubeconfig_content, data.k8s_context)
      : null;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-semibold text-fg">Authenticate</h2>
      </div>

      {platform === "aws" && data.auth_method === "assume_role" && (
        <Field label="Role ARN" required error={roleArnErr}>
          <Input
            value={data.role_arn}
            onChange={(e) => onChange({ role_arn: e.target.value })}
            onBlur={() => markTouched("role_arn")}
            placeholder="arn:aws:iam::123456789012:role/VentraReadOnly"
            autoComplete="off"
            className={cn(
              "mono",
              CREDENTIAL_INPUT_CLASS,
              roleArnErr && "border-bad-red/60 focus:border-bad-red",
            )}
          />
        </Field>
      )}

      {platform === "aws" && data.auth_method === "credentials" && (
        <div className="space-y-4">
          <Field label="Access Key ID" required error={accessKeyErr}>
            <Input
              value={data.aws_access_key_id}
              onChange={(e) => onChange({ aws_access_key_id: e.target.value })}
              onBlur={() => markTouched("aws_access_key_id")}
              placeholder="AKIAIOSFODNN7EXAMPLE"
              autoComplete="off"
              className={cn(
                "mono",
                CREDENTIAL_INPUT_CLASS,
                accessKeyErr && "border-bad-red/60 focus:border-bad-red",
              )}
            />
          </Field>

          <Field label="Secret Access Key" required={!editing}>
            <Input
              type="password"
              value={data.aws_secret_access_key}
              onChange={(e) => onChange({ aws_secret_access_key: e.target.value })}
              placeholder={
                editing ? "••••••••••••••••" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              }
              autoComplete="new-password"
              className={cn("mono", CREDENTIAL_INPUT_CLASS)}
            />
          </Field>

          <Field label="Session token (optional)">
            <Input
              type="password"
              value={data.aws_session_token}
              onChange={(e) => onChange({ aws_session_token: e.target.value })}
              placeholder={editing ? "••••••••••••••••" : "FwoGZXIvYXdzEBQaD..."}
              autoComplete="new-password"
              className={cn("mono", CREDENTIAL_INPUT_CLASS)}
            />
          </Field>
        </div>
      )}

      {platform === "aws" && <AwsPermissionScope />}

      {platform === "gcp" && data.auth_method === "service_account" && (
        <GcpServiceAccountKeyField
          value={data.gcp_service_account_json}
          onChange={(json) => onChange({ gcp_service_account_json: json })}
          editing={editing}
          error={gcpKeyErr}
          onBlur={() => markTouched("gcp_service_account_json")}
        />
      )}

      {platform === "gcp" && <GcpPermissionScope />}

      {platform === "m365" && (
        <div className="space-y-4">
          <Field label="Tenant ID" required error={tenantErr}>
            <Input
              value={data.azure_tenant_id}
              onChange={(e) => onChange({ azure_tenant_id: e.target.value })}
              onBlur={() => markTouched("azure_tenant_id")}
              placeholder="Enter the Tenant ID"
              autoComplete="off"
              className={cn(
                "mono",
                CREDENTIAL_INPUT_CLASS,
                tenantErr && "border-bad-red/60 focus:border-bad-red",
              )}
            />
          </Field>

          <Field label="Client ID" required error={clientErr}>
            <Input
              value={data.azure_client_id}
              onChange={(e) => onChange({ azure_client_id: e.target.value })}
              onBlur={() => markTouched("azure_client_id")}
              placeholder="Enter the Client ID"
              autoComplete="off"
              className={cn(
                "mono",
                CREDENTIAL_INPUT_CLASS,
                clientErr && "border-bad-red/60 focus:border-bad-red",
              )}
            />
          </Field>

          {data.auth_method === "client_secret" ? (
            <SecretField
              label="Client Secret"
              value={data.azure_client_secret}
              onChange={(v) => onChange({ azure_client_secret: v })}
              required={!editing}
              editing={editing}
              placeholder={editing ? "••••••••••••••••" : "Enter the Client Secret"}
            />
          ) : (
            <Field label="Certificate Content" required={!editing}>
              <textarea
                value={data.azure_client_certificate_content}
                onChange={(e) => onChange({ azure_client_certificate_content: e.target.value })}
                rows={12}
                spellCheck={false}
                placeholder={
                  editing
                    ? "Leave blank to keep the saved certificate"
                    : "Enter the base64 encoded certificate content"
                }
                className={LARGE_PASTE_TEXTAREA_CLASS}
              />
            </Field>
          )}
        </div>
      )}

      {platform === "azure" && data.auth_method === "service_principal" && (
        <div className="space-y-4">
          <Field label="Tenant ID" required error={tenantErr}>
            <Input
              value={data.azure_tenant_id}
              onChange={(e) => onChange({ azure_tenant_id: e.target.value })}
              onBlur={() => markTouched("azure_tenant_id")}
              placeholder="Enter the Tenant ID"
              autoComplete="off"
              className={cn(
                "mono",
                CREDENTIAL_INPUT_CLASS,
                tenantErr && "border-bad-red/60 focus:border-bad-red",
              )}
            />
          </Field>

          <Field label="Client ID" required error={clientErr}>
            <Input
              value={data.azure_client_id}
              onChange={(e) => onChange({ azure_client_id: e.target.value })}
              onBlur={() => markTouched("azure_client_id")}
              placeholder="Enter the Client ID"
              autoComplete="off"
              className={cn(
                "mono",
                CREDENTIAL_INPUT_CLASS,
                clientErr && "border-bad-red/60 focus:border-bad-red",
              )}
            />
          </Field>

          <SecretField
            label="Client Secret"
            value={data.azure_client_secret}
            onChange={(v) => onChange({ azure_client_secret: v })}
            required={!editing}
            editing={editing}
            placeholder={editing ? "••••••••••••••••" : "Enter the Client Secret"}
          />
        </div>
      )}

      {platform === "azure" && <AzurePermissionScope />}

      {platform === "m365" && <M365PermissionScope />}

      {platform === "kubernetes" && data.auth_method === "kubeconfig" && (
        <Field label="Kubeconfig Content" required={!editing} error={kubeconfigErr}>
          <textarea
            value={data.kubeconfig_content}
            onChange={(e) => onChange({ kubeconfig_content: e.target.value })}
            onBlur={() => markTouched("kubeconfig_content")}
            rows={12}
            spellCheck={false}
            placeholder={
              editing
                ? "Paste new kubeconfig YAML to replace the saved content, or leave blank"
                : "Paste your Kubeconfig YAML content here"
            }
            className={cn(
              LARGE_PASTE_TEXTAREA_CLASS,
              kubeconfigErr && "border-bad-red/60 focus:border-bad-red",
            )}
          />
        </Field>
      )}

      {platform === "kubernetes" && <KubernetesPermissionScope />}

      {platform && platform !== "kubernetes" && (
        <IamPolicyLinks platform={platform} />
      )}

      {!platform && (
        <p className="text-sm text-fg-subtle">Select a provider in step 1 to continue.</p>
      )}
    </div>
  );
}
