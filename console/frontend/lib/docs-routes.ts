import type { AcquirePlatform } from "./catalog";
import { CASE_PLATFORM_LABELS, isAcquirePlatform, type CasePlatform } from "./catalog";

export const DOCS_HREF = "/docs";

/** Documentation providers — mirrors case platform tabs (includes Kubernetes roadmap). */
export const DOC_PROVIDERS = ["aws", "azure", "gcp", "kubernetes"] as const;
export type DocProvider = (typeof DOC_PROVIDERS)[number];

export const DOC_PROVIDER_LABELS: Record<DocProvider, string> = {
  aws: CASE_PLATFORM_LABELS.aws,
  azure: CASE_PLATFORM_LABELS.azure,
  gcp: CASE_PLATFORM_LABELS.gcp,
  kubernetes: CASE_PLATFORM_LABELS.kubernetes,
};

export function isDocProvider(value: string): value is DocProvider {
  return (DOC_PROVIDERS as readonly string[]).includes(value.toLowerCase());
}

export function docsProviderHref(provider: DocProvider | string): string {
  return `/docs/${encodeURIComponent(provider.toLowerCase())}`;
}

export function docsCollectorHref(provider: DocProvider | string, collector: string): string {
  return `/docs/${encodeURIComponent(provider.toLowerCase())}/${encodeURIComponent(collector)}`;
}

/** Artifact registry `cloud` query values to load for a documentation provider page. */
export function artifactCloudsForProvider(provider: DocProvider): string[] {
  if (provider === "azure") return ["azure", "m365"];
  return [provider];
}

/** Resolve Acquire deep-link platform from an artifact's cloud field. */
export function acquirePlatformForArtifact(cloud: string): AcquirePlatform | null {
  const c = cloud.toLowerCase();
  return isAcquirePlatform(c) ? c : null;
}

export type IamPolicyRef = { label: string; path: string };

/** Repository-relative IAM policy files surfaced on provider/collector doc pages. */
export const PROVIDER_IAM_POLICIES: Partial<Record<DocProvider, IamPolicyRef[]>> = {
  aws: [
    {
      label: "Collector permissions",
      path: "docs/iam-policies/aws-collector-permissions.txt",
    },
    {
      label: "Read-only IAM policy (JSON)",
      path: "docs/iam-policies/aws-collector-readonly.json",
    },
  ],
  azure: [
    {
      label: "Azure ARM read-only",
      path: "docs/iam-policies/azure-collector-readonly.json",
    },
    {
      label: "Microsoft Graph (Entra)",
      path: "docs/iam-policies/azure-collector-graph.json",
    },
    {
      label: "M365 Unified Audit",
      path: "docs/iam-policies/azure-collector-m365.json",
    },
  ],
  gcp: [
    {
      label: "Collector permissions",
      path: "docs/iam-policies/gcp-collector-permissions.txt",
    },
    {
      label: "Read-only policy (JSON)",
      path: "docs/iam-policies/gcp-collector-readonly.json",
    },
  ],
};

export function docProviderLabel(provider: string): string {
  const key = provider.toLowerCase() as DocProvider;
  return DOC_PROVIDER_LABELS[key] ?? provider;
}

export function docProviderFromCasePlatform(platform: CasePlatform): DocProvider | null {
  if (isDocProvider(platform)) return platform;
  return null;
}
