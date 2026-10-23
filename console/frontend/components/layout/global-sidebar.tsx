"use client";

import {
  CASES_HREF,
  COLLECTION_KITS_HREF,
  CONFIG_ACQUIRE_HREF,
  CONFIG_COLLECTION_HREF,
  CONFIG_PROVIDERS_HREF,
  EXPORT_HREF,
  GITHUB_REPO_URL,
  normalizePathname,
} from "@/lib/routes";
import {
  DOC_PROVIDERS,
  DOC_PROVIDER_LABELS,
  DOC_SECTIONS,
  docSectionLabel,
  docsSectionHref,
  type DocProvider,
} from "@/lib/docs-routes";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { cn } from "@/lib/utils";
import {
  Activity,
  Boxes,
  Cable,
  ChevronDown,
  Download,
  FolderOpen,
  LayoutTemplate,
  Play,
  Shield,
  createLucideIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { LucideIcon } from "lucide-react";
import { useState } from "react";

/** lucide-react 1.x dropped brand icons; this is the outline mark it shipped as `Github` (ISC). */
const Github = createLucideIcon("Github", [
  [
    "path",
    {
      d: "M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4",
      key: "tonef",
    },
  ],
  ["path", { d: "M9 18c-4.51 2-5-2-7-2", key: "9comsn" }],
]);

type NavItem = { href: string; label: string; icon: LucideIcon; match?: (p: string) => boolean };

const CONFIGURATION: NavItem[] = [
  { href: CASES_HREF, label: "Cases", icon: FolderOpen },
  {
    href: COLLECTION_KITS_HREF,
    label: "Collection Kits",
    icon: LayoutTemplate,
    match: (p) => p.startsWith(COLLECTION_KITS_HREF),
  },
  {
    href: CONFIG_ACQUIRE_HREF,
    label: "Acquire",
    icon: Boxes,
    match: (p) => p.startsWith(CONFIG_ACQUIRE_HREF) || p.startsWith("/acquire"),
  },
  {
    href: CONFIG_COLLECTION_HREF,
    label: "Scans",
    icon: Activity,
    match: (p) => p === CONFIG_COLLECTION_HREF || p.startsWith("/runs/"),
  },
  {
    href: CONFIG_PROVIDERS_HREF,
    label: "Authentication",
    icon: Cable,
    match: (p) => p.startsWith("/config/providers") || p.startsWith("/config/connections"),
  },
  {
    href: EXPORT_HREF,
    label: "Export",
    icon: Download,
    match: (p) => p.startsWith(EXPORT_HREF),
  },
];

function NavLink({ item, pathname }: { item: NavItem; pathname: string }) {
  const active = item.match ? item.match(pathname) : pathname === item.href;
  const Icon = item.icon;
  return (
    <Link href={item.href} className={cn("sb-nav-item", active && "active")}>
      <Icon className="shrink-0" strokeWidth={1.75} aria-hidden />
      {item.label}
    </Link>
  );
}

function NavSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <>
      <div className="sb-nav-section">{title}</div>
      {children}
    </>
  );
}

function DocsProviderNav({
  provider,
  pathname,
  expanded,
  onToggle,
}: {
  provider: DocProvider;
  pathname: string;
  expanded: boolean;
  onToggle: () => void;
}) {
  const base = `/docs/${provider}`;
  const providerActive = pathname.startsWith(base);
  return (
    <div>
      <div className="flex items-center">
        <Link
          href={docsSectionHref(provider, "authentication")}
          className={cn("sb-nav-item min-w-0 flex-1", providerActive && "active")}
        >
          <CloudProviderIcon cloud={provider} className="shrink-0" />
          <span className="truncate">{DOC_PROVIDER_LABELS[provider]}</span>
        </Link>
        <button
          type="button"
          onClick={onToggle}
          className="mr-1 rounded p-1 text-fg-faint hover:bg-surface-2 hover:text-fg"
          aria-expanded={expanded}
          aria-label={`${expanded ? "Collapse" : "Expand"} ${DOC_PROVIDER_LABELS[provider]} documentation`}
        >
          <ChevronDown
            className={cn("h-3.5 w-3.5 transition-transform", expanded && "rotate-180")}
            aria-hidden
          />
        </button>
      </div>
      {expanded && (
        <div className="ml-6 space-y-0.5 border-l border-border pl-2">
          {DOC_SECTIONS.map((section) => {
            const href = docsSectionHref(provider, section.id);
            const active =
              pathname === href || pathname.startsWith(`${href}/`);
            return (
              <Link
                key={section.id}
                href={href}
                className={cn(
                  "block rounded-md px-3 py-1.5 text-sm transition-colors",
                  active
                    ? "font-medium text-accent"
                    : "font-normal text-fg-subtle hover:bg-surface-2 hover:text-fg",
                )}
              >
                {docSectionLabel(section.id, provider)}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function GlobalSidebar() {
  const pathname = normalizePathname(usePathname() || "/");
  const [manualExpand, setManualExpand] = useState<Record<string, boolean>>({});
  return (
    <aside className="app-sidebar">
      <div className="sb-brand-row">
        <Link href={CASES_HREF} className="sb-brand">
          <div className="sb-brand-mark">
            <Shield className="h-[19px] w-[19px]" strokeWidth={1.8} aria-hidden />
          </div>
          <div className="sb-brand-title">Ventra</div>
        </Link>
        <div className="sb-brand-actions">
          <a
            href={GITHUB_REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="sb-brand-action"
            title="Ventra on GitHub"
            aria-label="Ventra on GitHub"
          >
            <Github className="h-4 w-4" aria-hidden />
          </a>
        </div>
      </div>
      <div className="sb-cta">
        <Link
          href={COLLECTION_KITS_HREF}
          className="sb-primary-action flex w-full items-center justify-center gap-2 rounded-md border border-accent-cta/20 bg-accent-cta px-3 py-2 text-sm font-semibold text-accent-cta-fg shadow-[0_1px_0_rgb(255_255_255/0.25)_inset] transition-colors hover:bg-accent-cta/90"
          aria-label="Run collection"
        >
          <Play className="h-4 w-4 shrink-0" aria-hidden />
          <span>Run collection</span>
        </Link>
      </div>
      <nav className="sb-nav">
        <NavSection title="Configuration">
          {CONFIGURATION.map((item) => (
            <NavLink key={item.href} item={item} pathname={pathname} />
          ))}
        </NavSection>
        <NavSection title="Documentation">
          {DOC_PROVIDERS.map((provider) => {
            const expanded =
              manualExpand[provider] ?? pathname.startsWith(`/docs/${provider}`);
            return (
              <DocsProviderNav
                key={provider}
                provider={provider}
                pathname={pathname}
                expanded={expanded}
                onToggle={() =>
                  setManualExpand((prev) => ({
                    ...prev,
                    [provider]: !(prev[provider] ?? pathname.startsWith(`/docs/${provider}`)),
                  }))
                }
              />
            );
          })}
        </NavSection>
      </nav>
    </aside>
  );
}
