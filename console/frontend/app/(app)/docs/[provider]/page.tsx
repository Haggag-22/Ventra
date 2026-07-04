"use client";

import {
  DocComingSoon,
  DocLayout,
  DocPageHeader,
} from "@/components/docs/doc-layout";
import { ArtifactIcon } from "@/components/artifact-icon";
import { EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { groupArtifactsByCategory } from "@/lib/docs-data";
import {
  DOC_PROVIDER_LABELS,
  PROVIDER_IAM_POLICIES,
  artifactCloudsForProvider,
  docsCollectorHref,
  isDocProvider,
  type DocProvider,
} from "@/lib/docs-routes";
import { acquireHref } from "@/lib/routes";
import { displayCategoryLabel } from "@/lib/format";
import type { Artifact } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { BookOpen, ChevronRight, FileKey, Play } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { use, useMemo } from "react";

async function loadProviderArtifacts(provider: DocProvider): Promise<Artifact[]> {
  const clouds = artifactCloudsForProvider(provider);
  const results = await Promise.all(clouds.map((cloud) => api.artifacts(cloud)));
  const byCollector = new Map<string, Artifact>();
  for (const result of results) {
    for (const artifact of result.artifacts) {
      if (artifact.selectable === false) continue;
      if (!byCollector.has(artifact.collector)) byCollector.set(artifact.collector, artifact);
    }
  }
  return [...byCollector.values()];
}

export default function DocsProviderPage({
  params,
}: {
  params: Promise<{ provider: string }>;
}) {
  const { provider: raw } = use(params);
  const provider = raw.toLowerCase();
  if (!isDocProvider(provider)) notFound();

  const artifacts = useQuery({
    queryKey: ["docs", "artifacts", provider],
    queryFn: () => loadProviderArtifacts(provider),
    staleTime: 120_000,
  });

  const groups = useMemo(
    () => groupArtifactsByCategory(artifacts.data ?? []),
    [artifacts.data],
  );
  const iamPolicies = PROVIDER_IAM_POLICIES[provider] ?? [];

  return (
    <DocLayout
      provider={provider}
      artifacts={artifacts.data}
      artifactsPending={artifacts.isPending}
    >
      <DocPageHeader
        title={`${DOC_PROVIDER_LABELS[provider]} collectors`}
        description="Browse collectors grouped by category. Select a collector for permissions, configuration, and output details."
      />

      <div className="px-6 py-8">
        {iamPolicies.length > 0 && (
          <div className="mb-8 rounded-lg border border-border bg-surface-2 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-fg">
              <FileKey className="h-4 w-4 text-accent" aria-hidden />
              IAM policies
            </div>
            <p className="mt-1 text-sm text-fg-subtle">
              Read-only policy files in the Ventra repository for client security review.
            </p>
            <ul className="mt-3 space-y-1.5">
              {iamPolicies.map((policy) => (
                <li key={policy.path}>
                  <code className="mono rounded border border-border/60 bg-surface px-2 py-1 text-xs text-fg">
                    {policy.path}
                  </code>
                  <span className="ml-2 text-xs text-fg-subtle">{policy.label}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {artifacts.isPending ? (
          <LoadingPanel label="Loading collectors…" />
        ) : artifacts.isError ? (
          <EmptyState
            icon={BookOpen}
            title="Can't load collectors"
            description={
              artifacts.error instanceof Error ? artifacts.error.message : "Unknown error"
            }
          />
        ) : groups.length === 0 ? (
          <DocComingSoon label="Collector documentation for this provider is coming soon." />
        ) : (
          <div className="space-y-8">
            {groups.map((group) => (
              <section key={group.category}>
                <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                  {displayCategoryLabel(group.category)}
                </h2>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {group.items.map((artifact) => (
                    <Link
                      key={artifact.collector}
                      href={docsCollectorHref(provider, artifact.collector)}
                      className="group flex items-start gap-3 rounded-lg border border-border bg-surface p-4 transition-colors hover:border-accent/40 hover:bg-surface-2"
                    >
                      <ArtifactIcon
                        collector={artifact.collector}
                        cloud={artifact.cloud}
                        className="mt-0.5 h-8 w-8 shrink-0"
                      />
                      <div className="min-w-0 flex-1">
                        <p className="font-medium text-fg group-hover:text-accent">
                          {artifact.name || displayArtifactLabel(artifact.collector)}
                        </p>
                        {artifact.description && (
                          <p className="mt-1 line-clamp-2 text-xs text-fg-subtle">
                            {artifact.description}
                          </p>
                        )}
                      </div>
                      <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-fg-faint group-hover:text-accent" />
                    </Link>
                  ))}
                </div>
              </section>
            ))}
          </div>
        )}

        {provider !== "kubernetes" && groups.length > 0 && (
          <div className="mt-8 flex justify-end">
            <Link
              href={acquireHref({ cloud: provider })}
              className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 text-xs text-fg transition-colors hover:bg-surface-2/70"
            >
              <Play className="h-4 w-4" aria-hidden />
              Open Acquire
            </Link>
          </div>
        )}
      </div>
    </DocLayout>
  );
}
