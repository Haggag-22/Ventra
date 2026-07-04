"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { LoadingPanel } from "@/components/ui";
import { displayCategoryLabel } from "@/lib/format";
import { groupArtifactsByCategory } from "@/lib/docs-data";
import {
  DOC_PROVIDERS,
  DOC_PROVIDER_LABELS,
  DOCS_HREF,
  docsCollectorHref,
  docsProviderHref,
  type DocProvider,
} from "@/lib/docs-routes";
import type { Artifact } from "@/lib/types";
import { cn } from "@/lib/utils";
import { BookOpen, ChevronRight } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

function DocsNavLink({
  href,
  active,
  children,
  className,
}: {
  href: string;
  active: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Link
      href={href}
      className={cn(
        "block rounded-md px-2.5 py-1.5 text-sm transition-colors",
        active
          ? "bg-accent/15 font-medium text-accent"
          : "text-fg-subtle hover:bg-surface-2 hover:text-fg",
        className,
      )}
    >
      {children}
    </Link>
  );
}

export function DocLayout({
  provider,
  collector,
  artifacts,
  artifactsPending,
  children,
}: {
  provider?: DocProvider;
  collector?: string;
  artifacts?: Artifact[];
  artifactsPending?: boolean;
  children: ReactNode;
}) {
  const pathname = usePathname();
  const groups = artifacts ? groupArtifactsByCategory(artifacts) : [];

  return (
    <div className="flex min-h-full">
      <aside className="hidden w-56 shrink-0 border-r border-border bg-surface lg:block">
        <div className="sticky top-0 max-h-[calc(100vh-3.5rem)] overflow-y-auto p-4">
          <DocsNavLink href={DOCS_HREF} active={pathname === DOCS_HREF}>
            <span className="flex items-center gap-2">
              <BookOpen className="h-4 w-4 shrink-0" aria-hidden />
              Overview
            </span>
          </DocsNavLink>

          <div className="sb-nav-section mt-4 px-0">Providers</div>
          <nav className="space-y-0.5">
            {DOC_PROVIDERS.map((p) => (
              <DocsNavLink
                key={p}
                href={docsProviderHref(p)}
                active={provider === p && !collector}
              >
                <span className="flex items-center gap-2">
                  <CloudProviderIcon cloud={p} className="shrink-0" />
                  {DOC_PROVIDER_LABELS[p]}
                </span>
              </DocsNavLink>
            ))}
          </nav>

          {provider && (
            <>
              <div className="sb-nav-section mt-4 px-0">Collectors</div>
              {artifactsPending ? (
                <div className="py-6">
                  <LoadingPanel label="Loading collectors…" />
                </div>
              ) : groups.length === 0 ? (
                <p className="px-2.5 text-xs text-fg-subtle">No collectors yet.</p>
              ) : (
                <nav className="space-y-3">
                  {groups.map((group) => (
                    <div key={group.category}>
                      <p className="mb-1 px-2.5 text-2xs font-semibold uppercase tracking-wide text-fg-faint">
                        {displayCategoryLabel(group.category)}
                      </p>
                      <div className="space-y-0.5">
                        {group.items.map((item) => (
                          <DocsNavLink
                            key={item.collector}
                            href={docsCollectorHref(provider, item.collector)}
                            active={collector === item.collector}
                            className="truncate"
                          >
                            {item.name}
                          </DocsNavLink>
                        ))}
                      </div>
                    </div>
                  ))}
                </nav>
              )}
            </>
          )}
        </div>
      </aside>

      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

export function DocPageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="border-b border-border bg-surface px-6 py-5">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold tracking-tight text-fg">{title}</h1>
          {description && <p className="mt-1 max-w-3xl text-sm text-fg-subtle">{description}</p>}
        </div>
        {actions}
      </div>
    </div>
  );
}

export function DocSection({
  title,
  children,
  id,
}: {
  title: string;
  children: ReactNode;
  id?: string;
}) {
  return (
    <section id={id} className="scroll-mt-6">
      <h2 className="text-sm font-semibold text-fg">{title}</h2>
      <div className="mt-2 text-sm leading-relaxed text-fg-subtle">{children}</div>
    </section>
  );
}

export function DocComingSoon({ label = "Coming soon" }: { label?: string }) {
  return (
    <p className="rounded-md border border-dashed border-border bg-surface-2 px-3 py-2 text-sm italic text-fg-faint">
      {label}
    </p>
  );
}

export function DocProviderCard({
  provider,
  collectorCount,
  description,
}: {
  provider: DocProvider;
  collectorCount?: number;
  description?: string;
}) {
  return (
    <Link
      href={docsProviderHref(provider)}
      className="group flex flex-col rounded-lg border border-border bg-surface p-5 transition-colors hover:border-accent/40 hover:bg-surface-2"
    >
      <div className="flex items-center gap-3">
        <CloudProviderIcon cloud={provider} className="shrink-0" />
        <div className="min-w-0 flex-1">
          <h2 className="font-semibold text-fg">{DOC_PROVIDER_LABELS[provider]}</h2>
          {typeof collectorCount === "number" && (
            <p className="text-xs text-fg-subtle">
              {collectorCount} collector{collectorCount === 1 ? "" : "s"}
            </p>
          )}
        </div>
        <ChevronRight className="h-4 w-4 shrink-0 text-fg-faint transition-transform group-hover:translate-x-0.5 group-hover:text-accent" />
      </div>
      {description && <p className="mt-3 text-sm text-fg-subtle">{description}</p>}
    </Link>
  );
}
