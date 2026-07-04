"use client";

import { api } from "@/lib/api";
import {
  CASES_HREF,
  COLLECTION_KITS_HREF,
  CONFIG_ACQUIRE_HREF,
  CONFIG_COLLECTION_HREF,
  CONFIG_PROVIDERS_HREF,
  SETTINGS_HREF,
} from "@/lib/routes";
import { DOCS_HREF, docsProviderHref, DOC_PROVIDERS, DOC_PROVIDER_LABELS, type DocProvider } from "@/lib/docs-routes";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  BookOpen,
  Cable,
  FolderOpen,
  LayoutTemplate,
  PackageOpen,
  Play,
  Settings,
  Shield,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { LucideIcon } from "lucide-react";

type NavItem = { href: string; label: string; icon: LucideIcon; match?: (p: string) => boolean };

const HOME: NavItem[] = [{ href: CASES_HREF, label: "Cases", icon: FolderOpen }];

const COLLECTION_KIT: NavItem[] = [
  {
    href: COLLECTION_KITS_HREF,
    label: "Saved kits",
    icon: LayoutTemplate,
    match: (p) => p.startsWith(COLLECTION_KITS_HREF),
  },
];

const CONFIGURATION: NavItem[] = [
  {
    href: CONFIG_ACQUIRE_HREF,
    label: "Acquire",
    icon: PackageOpen,
    match: (p) => p.startsWith(CONFIG_ACQUIRE_HREF) || p.startsWith("/acquire"),
  },
  {
    href: CONFIG_PROVIDERS_HREF,
    label: "Providers",
    icon: Cable,
    match: (p) => p.startsWith("/config/providers") || p.startsWith("/config/connections"),
  },
  {
    href: CONFIG_COLLECTION_HREF,
    label: "Collection",
    icon: Activity,
    match: (p) => p === CONFIG_COLLECTION_HREF || p.startsWith("/runs/"),
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

function DocsProviderLink({ provider, pathname }: { provider: DocProvider; pathname: string }) {
  const href = docsProviderHref(provider);
  const active = pathname.startsWith(href);
  return (
    <Link href={href} className={cn("sb-nav-item", active && "active")}>
      <CloudProviderIcon cloud={provider} className="shrink-0" />
      {DOC_PROVIDER_LABELS[provider]}
    </Link>
  );
}

export function GlobalSidebar() {
  const pathname = usePathname();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, staleTime: 60_000 });

  return (
    <aside className="app-sidebar">
      <Link href={CASES_HREF} className="sb-brand">
        <div className="sb-brand-mark">
          <Shield className="h-[19px] w-[19px]" strokeWidth={1.8} aria-hidden />
        </div>
        <div className="sb-brand-title">Ventra</div>
      </Link>

      <div className="px-3 pt-3">
        <Link
          href={COLLECTION_KITS_HREF}
          className="sb-primary-action flex w-full items-center justify-center gap-2 rounded-md border border-accent-cta/20 bg-accent-cta px-3 py-2.5 text-sm font-semibold text-accent-cta-fg shadow-[0_1px_0_rgb(255_255_255/0.25)_inset] transition-colors hover:bg-accent-cta/90"
        >
          <Play className="h-4 w-4" aria-hidden />
          <span>Run collection</span>
        </Link>
      </div>

      <nav className="sb-nav">
        <NavSection title="Home">
          {HOME.map((item) => (
            <NavLink key={item.href} item={item} pathname={pathname} />
          ))}
        </NavSection>

        <NavSection title="Collection kit">
          {COLLECTION_KIT.map((item) => (
            <NavLink key={item.href} item={item} pathname={pathname} />
          ))}
        </NavSection>

        <NavSection title="Configuration">
          {CONFIGURATION.map((item) => (
            <NavLink key={item.href} item={item} pathname={pathname} />
          ))}
        </NavSection>

        <NavSection title="Documentation">
          <NavLink
            item={{
              href: DOCS_HREF,
              label: "Overview",
              icon: BookOpen,
              match: (p) => p === DOCS_HREF,
            }}
            pathname={pathname}
          />
          {DOC_PROVIDERS.map((provider) => (
            <DocsProviderLink key={provider} provider={provider} pathname={pathname} />
          ))}
        </NavSection>
      </nav>

      <div className="sb-footer space-y-2">
        <div className="sb-footer-meta flex items-center justify-between gap-2">
          <span className="mono">v{health.data?.version ?? "—"}</span>
          <span className="inline-flex items-center gap-1.5">
            <span className="sb-readonly-dot" />
            Online
          </span>
        </div>
        <Link
          href={SETTINGS_HREF}
          className={cn("sb-nav-item", pathname === SETTINGS_HREF && "active")}
        >
          <Settings className="shrink-0" strokeWidth={1.75} aria-hidden />
          Settings
        </Link>
      </div>
    </aside>
  );
}
