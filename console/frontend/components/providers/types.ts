import type { Connection } from "@/lib/api";
import { ACQUIRE_PLATFORM_LABELS, CASE_PLATFORM_LABELS, type CasePlatform } from "@/lib/catalog";

export const PROVIDER_PLATFORMS = [
  { id: "aws", label: "Amazon Web Services", searchable: "aws amazon web services" },
  { id: "gcp", label: "Google Cloud Platform", searchable: "gcp google cloud platform" },
  { id: "azure", label: "Microsoft Azure", searchable: "azure microsoft" },
  { id: "kubernetes", label: "Kubernetes", searchable: "kubernetes k8s" },
] as const;

export type SelectableProviderPlatform = (typeof PROVIDER_PLATFORMS)[number]["id"];
/** Connection platforms. Kubernetes stays in the type when the picker hides it. */
export type ProviderPlatform = SelectableProviderPlatform;

export const WIZARD_STEPS = [
  { id: "link", label: "Link a provider", description: "Choose cloud platform" },
  { id: "details", label: "Provider details", description: "Name and scope" },
  { id: "auth_method", label: "Authentication method", description: "Choose how to connect" },
  { id: "auth", label: "Authenticate", description: "Enter credentials" },
  { id: "validate", label: "Validate connection", description: "Test and save" },
] as const;

export type WizardStepId = (typeof WIZARD_STEPS)[number]["id"];

export type AwsAuthMethod = "assume_role" | "credentials";
export type GcpAuthMethod = "service_account" | "adc";
export type AzureAuthMethod = "service_principal";
export type K8sAuthMethod = "kubeconfig";
export type ProviderAuthMethod =
  | AwsAuthMethod
  | GcpAuthMethod
  | AzureAuthMethod
  | K8sAuthMethod;

export type ProviderWizardData = {
  platform: ProviderPlatform | "";
  name: string;
  alias: string;
  auth_method: ProviderAuthMethod;
  role_arn: string;
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_session_token: string;
  aws_account_id: string;
  project: string;
  subscription: string;
  azure_tenant_id: string;
  azure_client_id: string;
  azure_client_secret: string;
  gcp_service_account_json: string;
  k8s_context: string;
  kubeconfig_content: string;
};

export const EMPTY_WIZARD_DATA: ProviderWizardData = {
  platform: "",
  name: "",
  alias: "",
  auth_method: "credentials",
  role_arn: "",
  aws_access_key_id: "",
  aws_secret_access_key: "",
  aws_session_token: "",
  aws_account_id: "",
  project: "",
  subscription: "",
  azure_tenant_id: "",
  azure_client_id: "",
  azure_client_secret: "",
  gcp_service_account_json: "",
  k8s_context: "",
  kubeconfig_content: "",
};

export function platformLabel(platform: string): string {
  if (platform in ACQUIRE_PLATFORM_LABELS) {
    return ACQUIRE_PLATFORM_LABELS[platform as keyof typeof ACQUIRE_PLATFORM_LABELS];
  }
  if (platform in CASE_PLATFORM_LABELS) {
    return CASE_PLATFORM_LABELS[platform as CasePlatform];
  }
  return SHORT_PLATFORM_LABELS[platform] ?? platform;
}

function resolveAwsAuthMethod(conn: Connection): AwsAuthMethod {
  const method = (conn.auth_method || "").trim().toLowerCase();
  if (method === "assume_role" || Boolean(conn.role_arn?.trim())) return "assume_role";
  return "credentials";
}

function resolveGcpAuthMethod(conn: Connection): GcpAuthMethod {
  const method = (conn.auth_method || "").trim().toLowerCase();
  if (method === "adc") return "adc";
  return "service_account";
}

export function awsAuthMethodLabel(method: ProviderAuthMethod): string {
  return method === "assume_role" ? "IAM Role" : "Credentials";
}

export function gcpAuthMethodLabel(method: ProviderAuthMethod): string {
  return method === "adc" ? "Application Default Credentials" : "Service Account Key";
}

export function azureAuthMethodLabel(_method: ProviderAuthMethod): string {
  return "Service principal";
}

function resolveAzureAuthMethod(conn: Connection): AzureAuthMethod {
  const method = (conn.auth_method || "").trim().toLowerCase();
  if (method === "credentials" || method === "service_principal") return "service_principal";
  return "service_principal";
}

export function k8sAuthMethodLabel(_method: ProviderAuthMethod): string {
  return "Kubeconfig";
}

export function defaultAuthMethodForPlatform(platform: ProviderPlatform): ProviderAuthMethod {
  if (platform === "gcp") return "service_account";
  if (platform === "aws") return "credentials";
  if (platform === "azure") return "service_principal";
  if (platform === "kubernetes") return "kubeconfig";
  return "credentials";
}

export function connectionToWizardData(conn: Connection): ProviderWizardData {
  const platform = (conn.platform as ProviderPlatform) || "";
  return {
    platform,
    name: conn.name || "",
    alias: conn.alias || "",
    auth_method:
      platform === "aws"
        ? resolveAwsAuthMethod(conn)
        : platform === "gcp"
          ? resolveGcpAuthMethod(conn)
          : platform === "azure"
            ? resolveAzureAuthMethod(conn)
            : platform === "kubernetes"
                ? "kubeconfig"
                : "credentials",
    role_arn: conn.role_arn || "",
    aws_access_key_id: conn.aws_access_key_id || "",
    aws_secret_access_key: "",
    aws_session_token: "",
    aws_account_id: conn.aws_account_id || "",
    project: conn.project || "",
    subscription: conn.subscription || "",
    azure_tenant_id: conn.azure_tenant_id || "",
    azure_client_id: conn.azure_client_id || "",
    azure_client_secret: "",
    gcp_service_account_json: "",
    k8s_context: conn.k8s_context || "",
    kubeconfig_content: "",
  };
}

export function wizardDataToConnection(
  data: ProviderWizardData,
  options?: {
    omitEmptySecret?: boolean;
    omitEmptySessionToken?: boolean;
    omitEmptyGcpKey?: boolean;
    omitEmptyAzureSecret?: boolean;
    omitEmptyKubeconfig?: boolean;
  },
): Omit<Connection, "id" | "created_at" | "last_tested_at" | "last_test_ok"> {
  const platform = data.platform || "aws";
  const name =
    data.name.trim() ||
    data.alias.trim() ||
    `${platformLabel(platform)} provider`;

  const payload: Omit<Connection, "id" | "created_at" | "last_tested_at" | "last_test_ok"> = {
    name,
    alias: data.alias.trim(),
    platform,
    auth_method:
      platform === "aws"
        ? data.auth_method
        : platform === "gcp"
          ? data.auth_method === "adc"
            ? "adc"
            : "service_account"
          : platform === "azure"
            ? "service_principal"
            : platform === "kubernetes"
                ? "kubeconfig"
                : "default",
    aws_account_id: data.aws_account_id.trim(),
    project: data.project.trim(),
    subscription: data.subscription.trim(),
    azure_tenant_id: data.azure_tenant_id.trim(),
    azure_client_id: data.azure_client_id.trim(),
  };

  if (platform === "aws") {
    if (data.auth_method === "assume_role") {
      payload.role_arn = data.role_arn.trim();
      payload.aws_access_key_id = "";
      payload.aws_secret_access_key = "";
      payload.aws_session_token = "";
    } else {
      payload.role_arn = "";
      payload.aws_access_key_id = data.aws_access_key_id.trim();
      const secret = data.aws_secret_access_key.trim();
      if (secret || !options?.omitEmptySecret) {
        payload.aws_secret_access_key = secret;
      }
      const sessionToken = data.aws_session_token.trim();
      if (sessionToken || !options?.omitEmptySessionToken) {
        payload.aws_session_token = sessionToken;
      }
    }
  }

  if (platform === "gcp") {
    if (data.auth_method === "adc") {
      payload.gcp_service_account_json = "";
    } else {
      const gcpKey = data.gcp_service_account_json.trim();
      if (gcpKey || !options?.omitEmptyGcpKey) {
        payload.gcp_service_account_json = gcpKey;
      }
    }
  }

  if (platform === "kubernetes") {
    payload.k8s_context = data.k8s_context.trim();
    const kubeconfig = data.kubeconfig_content.trim();
    if (kubeconfig || !options?.omitEmptyKubeconfig) {
      payload.kubeconfig_content = kubeconfig;
    }
  }

  if (platform === "azure") {
    const azureSecret = data.azure_client_secret.trim();
    if (azureSecret || !options?.omitEmptyAzureSecret) {
      payload.azure_client_secret = azureSecret;
    }
  }

  return payload;
}

export function truncateId(id: string, head = 8, tail = 4): string {
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

export function formatProviderDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatAddedDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export type ProviderConnectionStatus = "connected" | "failed" | "untested";

/** Derive status from last_test_ok — never invent other fields. */
export function providerConnectionStatus(conn: Connection): ProviderConnectionStatus {
  if (conn.last_test_ok === true) return "connected";
  if (conn.last_test_ok === false) return "failed";
  return "untested";
}

export function isProviderConnected(conn: Connection): boolean {
  return providerConnectionStatus(conn) === "connected";
}

export function isProviderFailed(conn: Connection): boolean {
  return providerConnectionStatus(conn) === "failed";
}

export function isProviderUntested(conn: Connection): boolean {
  return providerConnectionStatus(conn) === "untested";
}

const SHORT_PLATFORM_LABELS: Record<string, string> = {
  aws: "AWS",
  gcp: "GCP",
  azure: "Azure",
  kubernetes: "Kubernetes",
};

export function shortPlatformLabel(platform: string): string {
  return SHORT_PLATFORM_LABELS[platform] ?? platform.toUpperCase();
}

/** Primary row title — alias when set, otherwise connection name. */
export function providerDisplayName(conn: Connection): string {
  return conn.alias?.trim() || conn.name;
}
