import type { AcquirePlatform, Cloud } from "./catalog";
import {
  docProviderLabel,
  docsDefaultHref,
  docSectionLabel,
  isDocProvider,
  isDocSection,
} from "./docs-routes";

/** Canonical URL for the cases list (outside any open case). */
export const CASES_HREF = "/cases";

/** Drop a trailing slash so `/cases` and `/cases/` compare the same. Root stays `/`. */
export function normalizePathname(pathname: string): string {
  if (!pathname || pathname === "/") return pathname || "/";
  return pathname.replace(/\/+$/, "") || "/";
}

/**
 * True for an open case (`/cases/<id>/...`).
 * The cases list (`/cases` and `/cases/`) is the main page and keeps the global sidebar.
 */
export function isCaseWorkspacePath(pathname: string): boolean {
  const path = normalizePathname(pathname);
  return path.startsWith("/cases/") && !path.endsWith("/settings");
}

export const EXPORT_HREF = "/export";
export const CONFIG_ACQUIRE_HREF = "/config/acquire";
/** @deprecated Bookmarks — use CONFIG_ACQUIRE_HREF. */
export const ACQUIRE_HREF = CONFIG_ACQUIRE_HREF;
export const COLLECTION_KITS_HREF = "/collection-kits";
export const RUNS_HREF = "/runs";
/** @deprecated Bookmarks — redirects to Acquire run mode via `/runs/new`. */
export const RUNS_NEW_HREF = "/runs/new";

/** Build `/config/acquire?mode=run` with optional saved connection. */
export function acquireRunHref(connectionId?: string | null): string {
  const base = `${CONFIG_ACQUIRE_HREF}?mode=run`;
  return connectionId?.trim()
    ? `${base}&connection=${encodeURIComponent(connectionId.trim())}`
    : base;
}
export const SETTINGS_HREF = "/settings";
export const CONFIG_COLLECTION_HREF = "/config/collection";
export const CONFIG_PROVIDERS_HREF = "/config/providers";
/** Public GitHub repository for this product. */
export const GITHUB_REPO_URL = "https://github.com/Haggag-22/Ventra";
/** @deprecated Use CONFIG_PROVIDERS_HREF — kept for redirects and bookmarks. */
export const CONFIG_CONNECTIONS_HREF = "/config/connections";
/** @deprecated Saved kits live at COLLECTION_KITS_HREF — kept for redirects. */
export const CONFIG_PROFILES_HREF = "/config/profiles";
/** @deprecated GCP log backend is configured per kit on Acquire — kept for redirects. */
export const CONFIG_LOG_BACKENDS_HREF = "/config/log-backends";

export type AcquireHrefParams = {
  caseId?: string;
  cloud?: AcquirePlatform;
  /** Collector registry keys to pre-select in the kit cart. */
  collectors?: string[];
};

/** Build `/config/acquire` with optional case, cloud, and pre-selected collectors. */
export function acquireHref(params: AcquireHrefParams = {}): string {
  const sp = new URLSearchParams();
  if (params.caseId?.trim()) sp.set("case_id", params.caseId.trim());
  if (params.cloud) sp.set("cloud", params.cloud);
  if (params.collectors?.length) sp.set("collectors", params.collectors.join(","));
  const q = sp.toString();
  return q ? `${CONFIG_ACQUIRE_HREF}?${q}` : CONFIG_ACQUIRE_HREF;
}

export function collectionKitEditHref(profileId: string): string {
  return `${CONFIG_ACQUIRE_HREF}?profile=${encodeURIComponent(profileId)}`;
}

/** Default panel when opening a case (audit / CloudTrail timeline). */
export const DEFAULT_CASE_PANEL = "cloudtrail";

export function caseHref(caseId: string, panel = DEFAULT_CASE_PANEL): string {
  return `/cases/${encodeURIComponent(caseId)}/${panel}`;
}

export function runHref(runId: string): string {
  return `/runs/${encodeURIComponent(runId)}`;
}

export type BreadcrumbItem = { label: string; href?: string };

const PANEL_LABELS: Record<string, string> = {
  cloudtrail: "CloudTrail",
  cloudwatch: "CloudWatch Logs",
  search: "Findings",
  identity: "Identity",
  network: "Network",
  web: "Web",
  "kubernetes-audit": "Kubernetes audit",
  "data-access": "Data access",
  collection: "Collection coverage",
  resources: "Resources",
  report: "Report",
  files: "Files",
  settings: "Settings",
};

/** Build breadcrumb trail from a pathname (client-side). */
export function breadcrumbsFromPath(pathname: string, caseId?: string): BreadcrumbItem[] {
  const path = normalizePathname(pathname);
  const items: BreadcrumbItem[] = [{ label: "Cases", href: CASES_HREF }];

  if (path === CASES_HREF) return items;

  if (path.startsWith(EXPORT_HREF)) {
    items.push({ label: "Configuration" });
    items.push({ label: "Export" });
    return items;
  }

  if (path.startsWith("/collection-kits")) {
    items.push({ label: "Configuration" });
    items.push({ label: "Collection Kits" });
    return items;
  }

  if (path.startsWith(CONFIG_ACQUIRE_HREF) || path.startsWith("/acquire")) {
    items.push({ label: "Configuration" });
    items.push({ label: "Acquire" });
    return items;
  }

  if (path.startsWith("/runs")) {
    items.push({ label: "Configuration" });
    items.push({ label: "Scans", href: CONFIG_COLLECTION_HREF });
    if (path.startsWith("/runs/")) {
      const runId = path.split("/")[2];
      if (runId && runId !== "new") items.push({ label: runId });
    }
    return items;
  }

  if (path.startsWith("/config/")) {
    items.push({ label: "Configuration" });
    if (
      path.startsWith(CONFIG_PROVIDERS_HREF) ||
      path.startsWith(CONFIG_CONNECTIONS_HREF)
    ) {
      items.push({ label: "Authentication" });
    } else if (path.startsWith(CONFIG_ACQUIRE_HREF)) items.push({ label: "Acquire" });
    else if (path.startsWith(CONFIG_PROFILES_HREF)) items.push({ label: "Collection Kits" });
    else if (path.startsWith(CONFIG_LOG_BACKENDS_HREF)) items.push({ label: "Acquire" });
    else if (path.startsWith(CONFIG_COLLECTION_HREF)) items.push({ label: "Scans" });
    return items;
  }

  if (path === SETTINGS_HREF) {
    items.push({ label: "Settings" });
    return items;
  }

  if (path.startsWith("/docs")) {
    items.push({ label: "Documentation", href: docsDefaultHref() });
    const parts = path.split("/").filter(Boolean);
    const provider = parts[1];
    if (provider && isDocProvider(provider)) {
      items.push({
        label: docProviderLabel(provider),
        href: `/docs/${provider}/authentication`,
      });
      const section = parts[2];
      if (section && isDocSection(section)) {
        items.push({
          label: docSectionLabel(section, provider),
          href: `/docs/${provider}/${section}`,
        });
        if (section === "collectors" && parts[3]) {
          items.push({ label: decodeURIComponent(parts[3]).replace(/_/g, " ") });
        }
      }
    }
    return items;
  }

  const caseMatch = path.match(/^\/cases\/([^/]+)(?:\/(.*))?$/);
  if (caseMatch) {
    const id = decodeURIComponent(caseMatch[1]);
    items.push({ label: id, href: caseHref(id) });
    const rest = caseMatch[2];
    if (rest) {
      const segment = rest.split("/")[0];
      items.push({ label: PANEL_LABELS[segment] ?? segment.replace(/-/g, " ") });
    }
    return items;
  }

  if (caseId) {
    items.push({ label: caseId, href: caseHref(caseId) });
  }

  return items;
}

/** Rough collection readiness from case summary (0–100). */
export function caseReadinessPct(summary: {
  collection?: { collected?: string[]; gaps?: unknown[] };
}): number | null {
  const collected = summary.collection?.collected?.length ?? 0;
  const gaps = summary.collection?.gaps?.length ?? 0;
  const total = collected + gaps;
  if (total === 0) return null;
  return Math.round((collected / total) * 100);
}

export type { Cloud };
