"use client";

import {
  DocComingSoon,
  DocLayout,
  DocPageHeader,
  DocSection,
} from "@/components/docs/doc-layout";
import { ArtifactIcon } from "@/components/artifact-icon";
import { Badge, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { acquirePermissionModel } from "@/lib/catalog";
import {
  DOC_PROVIDER_LABELS,
  PROVIDER_IAM_POLICIES,
  acquirePlatformForArtifact,
  artifactCloudsForProvider,
  docsCollectorsHref,
  isDocProvider,
  type DocProvider,
} from "@/lib/docs-routes";
import { displayCategoryLabel } from "@/lib/format";
import { acquireHref } from "@/lib/routes";
import type { Artifact } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { BookOpen, Download, FileKey, Play } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

async function findCollectorArtifact(
  provider: DocProvider,
  collector: string,
): Promise<Artifact | null> {
  const clouds = artifactCloudsForProvider(provider);
  for (const cloud of clouds) {
    try {
      const artifact = await api.artifact(collector, cloud);
      if (artifact.selectable !== false) return artifact;
    } catch {
      // Try next cloud scope for multi-cloud providers (e.g. azure + m365).
    }
  }
  return null;
}

export default function DocsCollectorPage({
  params,
}: {
  params: { provider: string; collector: string };
}) {
  const { provider: rawProvider, collector: rawCollector } = params;
  const provider = rawProvider.toLowerCase();
  const collector = decodeURIComponent(rawCollector);
  if (!isDocProvider(provider)) notFound();

  const providerArtifacts = useQuery({
    queryKey: ["docs", "artifacts", provider],
    queryFn: async () => {
      const clouds = artifactCloudsForProvider(provider);
      const results = await Promise.all(clouds.map((cloud) => api.artifacts(cloud)));
      const items: Artifact[] = [];
      const seen = new Set<string>();
      for (const result of results) {
        for (const artifact of result.artifacts) {
          if (artifact.selectable === false || seen.has(artifact.collector)) continue;
          seen.add(artifact.collector);
          items.push(artifact);
        }
      }
      return items;
    },
    staleTime: 120_000,
  });

  const artifact = useQuery({
    queryKey: ["docs", "artifact", provider, collector],
    queryFn: () => findCollectorArtifact(provider, collector),
    staleTime: 120_000,
  });

  if (artifact.isSuccess && !artifact.data) notFound();

  const data = artifact.data;
  const acquirePlatform = data ? acquirePlatformForArtifact(data.cloud) : null;
  const iamPolicies = PROVIDER_IAM_POLICIES[provider] ?? [];
  const permissionModel = acquirePermissionModel(provider);

  return (
    <DocLayout
      provider={provider}
      section="collectors"
      collector={collector}
      artifacts={providerArtifacts.data}
      artifactsPending={providerArtifacts.isPending}
    >
      {artifact.isPending ? (
        <div className="m-6">
          <LoadingPanel label="Loading collector…" />
        </div>
      ) : artifact.isError ? (
        <div className="p-6">
          <EmptyState
            icon={BookOpen}
            title="Can't load collector"
            description={
              artifact.error instanceof Error ? artifact.error.message : "Unknown error"
            }
          />
        </div>
      ) : data ? (
        <>
          <DocPageHeader title={displayArtifactLabel(data.collector, data.cloud)} />

          <div className="page-shell">
            <div className="mb-8 flex flex-wrap items-center gap-3">
              <ArtifactIcon collector={data.collector} cloud={data.cloud} className="h-10 w-10" />
              <div className="flex flex-wrap gap-2">
                <Badge>{displayCategoryLabel(data.category || "Other")}</Badge>
                <Badge className="mono">{data.collector}</Badge>
                {data.version && <Badge className="mono">v{data.version}</Badge>}
              </div>
            </div>

            <div className="max-w-3xl space-y-8">
              <DocSection title="Overview">
                {data.description ? (
                  <p>{data.description}</p>
                ) : (
                  <DocComingSoon />
                )}
              </DocSection>

              <DocSection title="Required permissions">
                {data.required_actions?.length ? (
                  <div className="space-y-3">
                    <p>
                      This collector requires{" "}
                      <span className="mono font-medium text-fg">
                        {data.required_actions.length}
                      </span>{" "}
                      narrowed {permissionModel} action
                      {data.required_actions.length === 1 ? "" : "s"} in the generated kit
                      policy.
                    </p>
                    <ul className="max-h-48 overflow-y-auto rounded-md border border-border bg-surface-2 p-3">
                      {data.required_actions.map((action) => (
                        <li key={action} className="mono text-xs text-fg-subtle">
                          {action}
                        </li>
                      ))}
                    </ul>
                    {iamPolicies.length > 0 && (
                      <div className="rounded-md border border-border bg-surface-2 p-3">
                        <div className="flex items-center gap-2 text-sm font-medium text-fg">
                          <FileKey className="h-4 w-4 text-accent" aria-hidden />
                          Provider {permissionModel} policies
                        </div>
                        <ul className="mt-2 space-y-1.5">
                          {iamPolicies.map((policy) => (
                            <li key={policy.path}>
                              <a
                                href={policy.publicPath}
                                download
                                className="inline-flex items-center gap-1.5 text-xs text-accent hover:underline"
                              >
                                {policy.label}
                                <Download className="h-3 w-3" aria-hidden />
                              </a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ) : (
                  <DocComingSoon />
                )}
              </DocSection>

              <DocSection title="Configuration">
                {data.parameters && Object.keys(data.parameters).length > 0 ? (
                  <ul className="space-y-2">
                    {Object.entries(data.parameters).map(([name, meta]) => (
                      <li
                        key={name}
                        className="rounded-md border border-border bg-surface-2 px-3 py-2"
                      >
                        <span className="mono font-medium text-fg">{name}</span>
                        {typeof meta === "object" &&
                          meta !== null &&
                          "description" in meta &&
                          typeof (meta as { description?: string }).description === "string" && (
                            <p className="mt-1 text-xs text-fg-subtle">
                              {(meta as { description: string }).description}
                            </p>
                          )}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-fg-subtle">
                    No collector-specific parameters. Scope and time window are set in Acquire when
                    building the kit.
                  </p>
                )}
              </DocSection>

              <DocSection title="Output artifacts">
                {data.sources?.length ? (
                  <ul className="space-y-2">
                    {data.sources.map((source, index) => (
                      <li
                        key={`${source.type}-${index}`}
                        className="rounded-md border border-border bg-surface-2 px-3 py-2"
                      >
                        <span className="mono text-fg">{source.type}</span>
                        {source.format && (
                          <span className="text-fg-subtle"> · {source.format}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <DocComingSoon />
                )}
              </DocSection>
            </div>

            <div className="mt-10 flex flex-wrap gap-3 border-t border-border pt-6">
              <Link
                href={docsCollectorsHref(provider)}
                className="inline-flex h-7 items-center rounded-md border border-border bg-surface-2 px-2.5 text-xs text-fg transition-colors hover:bg-surface-2/70"
              >
                All {DOC_PROVIDER_LABELS[provider]} collectors
              </Link>
              {acquirePlatform && (
                <Link
                  href={acquireHref({
                    cloud: acquirePlatform,
                    collectors: [data.collector],
                  })}
                  className="inline-flex h-7 items-center gap-1.5 rounded-md bg-accent px-2.5 text-xs font-medium text-accent-fg transition-colors hover:bg-accent/90"
                >
                  <Play className="h-4 w-4" aria-hidden />
                  Add to Acquire
                </Link>
              )}
            </div>
          </div>
        </>
      ) : null}
    </DocLayout>
  );
}
