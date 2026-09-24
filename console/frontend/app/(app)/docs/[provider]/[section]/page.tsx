"use client";

import { DeploymentTemplateLinks } from "@/components/deployment-template-links";
import { LoadingPanel } from "@/components/ui";
import { docSectionContent, renderDocBlocks } from "@/lib/doc-content";
import { groupArtifactsByCategory } from "@/lib/docs-data";
import {
  DOC_PROVIDER_LABELS,
  PROVIDER_IAM_POLICIES,
  artifactCloudsForProvider,
  docSectionLabel,
  docsCollectorHref,
  docsSectionHref,
  isDocProvider,
  isDocSection,
  type DocProvider,
  type DocSectionId,
} from "@/lib/docs-routes";
import { deploymentTemplatesForProvider } from "@/lib/deployment-templates";
import { displayCategoryLabel } from "@/lib/format";
import { acquireHref } from "@/lib/routes";
import type { Artifact } from "@/lib/types";
import { api } from "@/lib/api";
import { ChevronRight, Download, FileKey, Play } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { useMemo } from "react";
import {
  DocComingSoon,
  DocLayout,
  DocPageHeader,
} from "@/components/docs/doc-layout";
import { ArtifactIcon } from "@/components/artifact-icon";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { useQuery } from "@tanstack/react-query";

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

function DocSectionBody({
  provider,
  section,
}: {
  provider: DocProvider;
  section: DocSectionId;
}) {
  const content = docSectionContent(provider, section);
  const templates = deploymentTemplatesForProvider(provider);
  const iamPolicies = PROVIDER_IAM_POLICIES[provider] ?? [];

  if (section === "collectors") {
    return <CollectorsSection provider={provider} />;
  }

  if (!content) {
    return <DocComingSoon label="Documentation for this section is coming soon." />;
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div className="space-y-4">{renderDocBlocks(content.blocks)}</div>

      {section === "authentication" && templates.length > 0 && (
        <DeploymentTemplateLinks templates={templates} />
      )}

      {section === "permissions" && iamPolicies.length > 0 && (
        <div className="rounded-lg border border-border bg-surface-2 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-fg">
            <FileKey className="h-4 w-4 text-accent" aria-hidden />
            Downloadable policy files
          </div>
          <ul className="mt-3 space-y-2">
            {iamPolicies.map((policy) => (
              <li key={policy.path}>
                <a
                  href={policy.publicPath}
                  download
                  className="inline-flex items-center gap-2 text-sm text-accent hover:underline"
                >
                  {policy.label}
                  <Download className="h-3.5 w-3.5" aria-hidden />
                </a>
                <p className="mt-0.5 font-mono text-2xs text-fg-faint">{policy.publicPath}</p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {section === "permissions" && templates.some((t) => t.kind !== "policy") && (
        <DeploymentTemplateLinks
          templates={templates.filter((t) => t.kind === "cloudformation" || t.kind === "terraform")}
          title="Infrastructure templates"
          description="Deploy the read-only principal with Terraform or CloudFormation before assigning manual policies."
        />
      )}
    </div>
  );
}

function CollectorsSection({ provider }: { provider: DocProvider }) {
  const artifacts = useQuery({
    queryKey: ["docs", "artifacts", provider],
    queryFn: () => loadProviderArtifacts(provider),
    staleTime: 120_000,
  });

  const groups = useMemo(
    () => groupArtifactsByCategory(artifacts.data ?? []),
    [artifacts.data],
  );

  if (provider === "kubernetes") {
    return (
      <DocComingSoon label="Kubernetes collectors are on the roadmap. Check back for audit and workload evidence documentation." />
    );
  }

  if (artifacts.isPending) return <LoadingPanel label="Loading collectors…" />;

  if (groups.length === 0) {
    return <DocComingSoon label="Collector documentation for this provider is coming soon." />;
  }

  return (
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
                    {displayArtifactLabel(artifact.collector, artifact.cloud)}
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

      <div className="flex justify-end border-t border-border pt-6">
        <Link
          href={acquireHref({
            cloud:
              provider === "aws" || provider === "azure" || provider === "gcp"
                ? provider
                : "aws",
          })}
          className="inline-flex h-8 items-center gap-1.5 rounded-md bg-accent px-3 text-xs font-medium text-accent-fg transition-colors hover:bg-accent/90"
        >
          <Play className="h-4 w-4" aria-hidden />
          Open Acquire
        </Link>
      </div>
    </div>
  );
}

export default function DocProviderSectionPage({
  params,
}: {
  params: { provider: string; section: string };
}) {
  const { provider: rawProvider, section: rawSection } = params;
  const provider = rawProvider.toLowerCase();
  const section = rawSection.toLowerCase();

  if (!isDocProvider(provider) || !isDocSection(section)) notFound();

  const artifacts = useQuery({
    queryKey: ["docs", "artifacts", provider],
    queryFn: () => loadProviderArtifacts(provider),
    staleTime: 120_000,
    enabled: section === "collectors",
  });

  const pageTitle =
    section === "collectors"
      ? `${DOC_PROVIDER_LABELS[provider]} collectors`
      : `${DOC_PROVIDER_LABELS[provider]} ${docSectionLabel(section, provider)}`;

  return (
    <DocLayout
      provider={provider}
      section={section}
      artifacts={artifacts.data}
      artifactsPending={artifacts.isPending}
    >
      <DocPageHeader title={pageTitle} />
      <div className="page-shell">
        <DocSectionBody provider={provider} section={section} />
      </div>
    </DocLayout>
  );
}
