import type { AcquirePlatform } from "./catalog";
import { CASE_PLATFORM_LABELS, isAcquirePlatform, type CasePlatform } from "./catalog";

export const DOCS_HREF = "/docs";

/** Documentation providers — mirrors case platform tabs (includes Kubernetes roadmap). */
export const DOC_PROVIDERS = ["aws", "azure", "gcp", "kubernetes"] as const;
export type DocProvider = (typeof DOC_PROVIDERS)[number];
export const DEFAULT_DOC_PROVIDER: DocProvider = "aws";

export const DOC_PROVIDER_LABELS: Record<DocProvider, string> = {
  aws: CASE_PLATFORM_LABELS.aws,
  azure: CASE_PLATFORM_LABELS.azure,
  gcp: CASE_PLATFORM_LABELS.gcp,
  kubernetes: CASE_PLATFORM_LABELS.kubernetes,
};

/** Top-level documentation sections per provider. */
export const DOC_SECTIONS = [
  { id: "authentication", label: "Authentication" },
  { id: "permissions", label: "Permissions" },
  { id: "connections", label: "Connections" },
  { id: "collectors", label: "Collectors" },
] as const;

export type DocSectionId = (typeof DOC_SECTIONS)[number]["id"];

export function isDocSection(value: string): value is DocSectionId {
  return DOC_SECTIONS.some((s) => s.id === value);
}

export function docSectionLabel(section: DocSectionId): string {
  return DOC_SECTIONS.find((s) => s.id === section)?.label ?? section;
}

export function isDocProvider(value: string): value is DocProvider {
  return (DOC_PROVIDERS as readonly string[]).includes(value.toLowerCase());
}

export function docsProviderHref(provider: DocProvider | string): string {
  return `/docs/${encodeURIComponent(provider.toLowerCase())}/authentication`;
}

export function docsDefaultHref(): string {
  return docsProviderHref(DEFAULT_DOC_PROVIDER);
}

export function docsSectionHref(provider: DocProvider | string, section: DocSectionId): string {
  return `/docs/${encodeURIComponent(provider.toLowerCase())}/${section}`;
}

export function docsCollectorHref(provider: DocProvider | string, collector: string): string {
  return `/docs/${encodeURIComponent(provider.toLowerCase())}/collectors/${encodeURIComponent(collector)}`;
}

export function docsCollectorsHref(provider: DocProvider | string): string {
  return docsSectionHref(provider, "collectors");
}

/** Artifact registry `cloud` query values to load for a documentation provider page. */
export function artifactCloudsForProvider(provider: DocProvider): string[] {
  return [provider];
}

/** Resolve Acquire deep-link platform from an artifact's cloud field. */
export function acquirePlatformForArtifact(cloud: string): AcquirePlatform | null {
  const c = cloud.toLowerCase();
  return isAcquirePlatform(c) ? c : null;
}

export type IamPolicyRef = { label: string; path: string; publicPath: string };

/** Repository-relative IAM policy files surfaced on provider/collector doc pages. */
export const PROVIDER_IAM_POLICIES: Partial<Record<DocProvider, IamPolicyRef[]>> = {
  aws: [
    {
      label: "Collector permissions",
      path: "docs/iam-policies/aws-collector-permissions.txt",
      publicPath: "/docs/iam-policies/aws-collector-permissions.txt",
    },
    {
      label: "Read-only IAM policy JSON",
      path: "docs/iam-policies/aws-collector-readonly.json",
      publicPath: "/docs/iam-policies/aws-collector-readonly.json",
    },
  ],
  azure: [
    {
      label: "Azure ARM read-only",
      path: "docs/iam-policies/azure-collector-readonly.json",
      publicPath: "/docs/iam-policies/azure-collector-readonly.json",
    },
    {
      label: "Microsoft Graph Entra",
      path: "docs/iam-policies/azure-collector-graph.json",
      publicPath: "/docs/iam-policies/azure-collector-graph.json",
    },
  ],
  gcp: [
    {
      label: "Collector permissions",
      path: "docs/iam-policies/gcp-collector-permissions.txt",
      publicPath: "/docs/iam-policies/gcp-collector-permissions.txt",
    },
    {
      label: "Read-only policy JSON",
      path: "docs/iam-policies/gcp-collector-readonly.json",
      publicPath: "/docs/iam-policies/gcp-collector-readonly.json",
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

export function isDocsPath(pathname: string): boolean {
  return pathname === DOCS_HREF || pathname.startsWith(`${DOCS_HREF}/`);
}

export function activeDocProvider(pathname: string): DocProvider | null {
  const parts = pathname.split("/").filter(Boolean);
  if (parts[0] !== "docs" || !parts[1]) return null;
  const provider = parts[1].toLowerCase();
  return isDocProvider(provider) ? provider : null;
}

export function activeDocSection(pathname: string): DocSectionId | null {
  const parts = pathname.split("/").filter(Boolean);
  if (parts[0] !== "docs" || !parts[2]) return null;
  const segment = parts[2].toLowerCase();
  if (isDocSection(segment)) return segment;
  return null;
}

export function activeDocCollector(pathname: string): string | null {
  const parts = pathname.split("/").filter(Boolean);
  if (parts[0] !== "docs" || parts[2] !== "collectors" || !parts[3]) return null;
  return decodeURIComponent(parts[3]);
}
