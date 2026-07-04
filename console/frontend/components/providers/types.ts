import type { Connection } from "@/lib/api";
import { ACQUIRE_PLATFORM_LABELS, CASE_PLATFORM_LABELS, type CasePlatform } from "@/lib/catalog";

export const PROVIDER_PLATFORMS = [
  { id: "aws", label: "Amazon Web Services", searchable: "aws amazon web services" },
  { id: "gcp", label: "Google Cloud Platform", searchable: "gcp google cloud platform" },
  { id: "azure", label: "Microsoft Azure", searchable: "azure microsoft" },
  { id: "m365", label: "Microsoft 365", searchable: "m365 microsoft 365 office" },
  { id: "kubernetes", label: "Kubernetes", searchable: "kubernetes k8s", comingSoon: true },
] as const;

export type ProviderPlatform = (typeof PROVIDER_PLATFORMS)[number]["id"];

export const WIZARD_STEPS = [
  { id: "link", label: "Link a provider", description: "Choose cloud platform" },
  { id: "details", label: "Provider details", description: "Name and scope" },
  { id: "auth", label: "Authenticate", description: "Server-side credentials" },
  { id: "validate", label: "Validate connection", description: "Test and save" },
] as const;

export type WizardStepId = (typeof WIZARD_STEPS)[number]["id"];

export type ProviderAuthMethod = "profile" | "role";

export type ProviderWizardData = {
  platform: ProviderPlatform | "";
  name: string;
  alias: string;
  auth_method: ProviderAuthMethod;
  profile_name: string;
  role_arn: string;
  aws_account_id: string;
  project: string;
  subscription: string;
  azure_tenant_id: string;
  azure_client_id: string;
  cluster_name: string;
};

export const EMPTY_WIZARD_DATA: ProviderWizardData = {
  platform: "",
  name: "",
  alias: "",
  auth_method: "profile",
  profile_name: "",
  role_arn: "",
  aws_account_id: "",
  project: "",
  subscription: "",
  azure_tenant_id: "",
  azure_client_id: "",
  cluster_name: "",
};

export function platformLabel(platform: string): string {
  if (platform in ACQUIRE_PLATFORM_LABELS) {
    return ACQUIRE_PLATFORM_LABELS[platform as keyof typeof ACQUIRE_PLATFORM_LABELS];
  }
  if (platform in CASE_PLATFORM_LABELS) {
    return CASE_PLATFORM_LABELS[platform as CasePlatform];
  }
  return platform;
}

export function connectionToWizardData(conn: Connection): ProviderWizardData {
  const authMethod: ProviderAuthMethod =
    conn.auth_method === "assume_role" || conn.role_arn ? "role" : "profile";
  return {
    platform: (conn.platform as ProviderPlatform) || "",
    name: conn.name || "",
    alias: conn.alias || "",
    auth_method: authMethod,
    profile_name: conn.profile_name || "",
    role_arn: conn.role_arn || "",
    aws_account_id: conn.aws_account_id || "",
    project: conn.project || "",
    subscription: conn.subscription || "",
    azure_tenant_id: conn.azure_tenant_id || "",
    azure_client_id: conn.azure_client_id || "",
    cluster_name: "",
  };
}

export function wizardDataToConnection(
  data: ProviderWizardData,
): Omit<Connection, "id" | "created_at" | "last_tested_at" | "last_test_ok"> {
  const platform = data.platform || "aws";
  const name =
    data.name.trim() ||
    data.alias.trim() ||
    `${platformLabel(platform)} provider`;

  return {
    name,
    alias: data.alias.trim(),
    platform,
    auth_method: data.auth_method === "role" ? "assume_role" : "profile",
    profile_name: data.auth_method === "profile" ? data.profile_name.trim() : "",
    role_arn: data.auth_method === "role" ? data.role_arn.trim() : "",
    aws_account_id: data.aws_account_id.trim(),
    project: data.project.trim(),
    subscription: data.subscription.trim(),
    azure_tenant_id: data.azure_tenant_id.trim(),
    azure_client_id: data.azure_client_id.trim(),
  };
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

export function isProviderConnected(conn: Connection): boolean {
  return conn.last_test_ok === true;
}

const SHORT_PLATFORM_LABELS: Record<string, string> = {
  aws: "AWS",
  gcp: "GCP",
  azure: "Azure",
  m365: "M365",
  kubernetes: "Kubernetes",
};

export function shortPlatformLabel(platform: string): string {
  return SHORT_PLATFORM_LABELS[platform] ?? platform.toUpperCase();
}

/** Primary row title — alias when set, otherwise connection name. */
export function providerDisplayName(conn: Connection): string {
  return conn.alias?.trim() || conn.name;
}

/** Secondary subtitle — platform scope (account, project, subscription, etc.). */
export function providerScopeSubtitle(conn: Connection): string | null {
  if (conn.aws_account_id?.trim()) return conn.aws_account_id.trim();
  if (conn.project?.trim()) return conn.project.trim();
  if (conn.subscription?.trim()) return conn.subscription.trim();
  if (conn.azure_tenant_id?.trim()) return conn.azure_tenant_id.trim();
  return null;
}
