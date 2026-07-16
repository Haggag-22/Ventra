import type { ProviderPlatform, SelectableProviderPlatform } from "./types";

/**
 * Presentational metadata for the provider connection wizard. Kept separate from
 * `types.ts` (which other panels import) so the wizard's copy/validation can evolve
 * without touching the shared connection model.
 */

export type ProviderMeta = {
  /** Full display label. */
  label: string;
  /** Compact label for chips. */
  short: string;
  /** How the credential reaches the cloud, shown in the trust diagram. */
  credentialLabel: string;
  /** The scope noun for auth step labels (account, project, …). */
  scopeNoun: string;
};

export const PROVIDER_META: Record<ProviderPlatform, ProviderMeta> = {
  aws: {
    label: "Amazon Web Services",
    short: "AWS",
    credentialLabel: "AWS access keys",
    scopeNoun: "account",
  },
  gcp: {
    label: "Google Cloud Platform",
    short: "GCP",
    credentialLabel: "Service account key (JSON)",
    scopeNoun: "project",
  },
  azure: {
    label: "Microsoft Azure",
    short: "Azure",
    credentialLabel: "Service principal (client secret)",
    scopeNoun: "subscription",
  },
  m365: {
    label: "M365",
    short: "M365",
    credentialLabel: "App registration (Graph + UAL)",
    scopeNoun: "tenant",
  },
  kubernetes: {
    label: "Kubernetes",
    short: "K8s",
    credentialLabel: "Kubeconfig context",
    scopeNoun: "cluster",
  },
};

/** Ordered platforms for the selection grid. */
export const PROVIDER_ORDER: SelectableProviderPlatform[] = ["aws", "gcp", "azure", "kubernetes"];

// ---- Field validation ------------------------------------------------------------------
// Validators treat an empty string as valid — required-ness is enforced by the step, so an
// untouched optional field never shows an error.

const ROLE_ARN_RE = /^arn:aws[a-z-]*:iam::\d{12}:role\/.+$/;
const ACCOUNT_ID_RE = /^\d{12}$/;
const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const ACCESS_KEY_ID_RE = /^[A-Z0-9]{16,128}$/;

export function validateAccessKeyId(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  return ACCESS_KEY_ID_RE.test(v)
    ? null
    : "Access Key IDs are 16–128 uppercase letters or digits.";
}

export function validateRoleArn(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  return ROLE_ARN_RE.test(v)
    ? null
    : "Expected arn:aws:iam::<account>:role/<name>.";
}

export function validateAccountId(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  return ACCOUNT_ID_RE.test(v) ? null : "AWS account IDs are 12 digits.";
}

export function validateGuid(value: string, label: string): string | null {
  const v = value.trim();
  if (!v) return null;
  return GUID_RE.test(v) ? null : `${label} must be a GUID.`;
}

const GCP_SA_REQUIRED = ["type", "project_id", "private_key", "client_email"] as const;

export function validateGcpServiceAccountJson(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(v) as Record<string, unknown>;
  } catch {
    return "Service account key must be valid JSON.";
  }
  if (parsed.type !== "service_account") {
    return 'JSON must be a GCP service account key (type: "service_account").';
  }
  const missing = GCP_SA_REQUIRED.filter((k) => !String(parsed[k] ?? "").trim());
  if (missing.length) {
    return `Missing required fields: ${missing.join(", ")}.`;
  }
  return null;
}

export function validateKubeconfigYaml(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  if (!v.includes("apiVersion") && !v.includes("contexts")) {
    return "Kubeconfig must include apiVersion and contexts.";
  }
  try {
    const parsed = JSON.parse(v) as unknown;
    if (typeof parsed === "object" && parsed !== null) return null;
  } catch {
    // fall through — kubeconfig is YAML, not JSON
  }
  const lines = v.split("\n");
  const hasContexts = lines.some((line) => /^\s*contexts\s*:/.test(line) || /^\s*-\s*name\s*:/.test(line));
  if (!hasContexts && !/contexts:/.test(v)) {
    return "Kubeconfig must include a contexts section.";
  }
  return null;
}

export function validateKubeconfigContext(kubeconfig: string, contextName: string): string | null {
  const yamlErr = validateKubeconfigYaml(kubeconfig);
  if (yamlErr) return yamlErr;
  const ctx = contextName.trim();
  if (!ctx) return "Kubernetes context is required.";
  const names: string[] = [];
  const ctxBlock = kubeconfig.match(/contexts:\s*\n([\s\S]*?)(?:\n\S|\s*$)/);
  if (ctxBlock) {
    for (const match of ctxBlock[1].matchAll(/-\s*name:\s*(.+)/g)) {
      names.push(match[1].trim().replace(/^["']|["']$/g, ""));
    }
  }
  if (!names.length) {
    for (const match of kubeconfig.matchAll(/name:\s*(.+)/g)) {
      const name = match[1].trim().replace(/^["']|["']$/g, "");
      if (name && !names.includes(name)) names.push(name);
    }
  }
  if (names.length && !names.includes(ctx)) {
    return `Context "${ctx}" not found in kubeconfig.`;
  }
  return null;
}
