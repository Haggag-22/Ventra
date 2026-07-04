"use client";

import {
  DocLayout,
  DocPageHeader,
  DocProviderCard,
} from "@/components/docs/doc-layout";
import { api } from "@/lib/api";
import {
  DOC_PROVIDERS,
  artifactCloudsForProvider,
  type DocProvider,
} from "@/lib/docs-routes";
import { useQueries } from "@tanstack/react-query";

const PROVIDER_INTROS: Record<DocProvider, string> = {
  aws: "CloudTrail, VPC flow, GuardDuty, IAM posture, and other AWS forensic collectors.",
  azure: "Activity logs, Entra ID, NSG flow, Defender, and M365 audit collectors.",
  gcp: "Cloud Audit Logs, VPC flow, SCC findings, and workload inventory collectors.",
  kubernetes: "Cluster audit and workload evidence collectors (roadmap).",
};

export default function DocsHubPage() {
  const counts = useQueries({
    queries: DOC_PROVIDERS.map((provider) => ({
      queryKey: ["docs", "artifact-count", provider],
      queryFn: async () => {
        const clouds = artifactCloudsForProvider(provider);
        const results = await Promise.all(clouds.map((cloud) => api.artifacts(cloud)));
        const seen = new Set<string>();
        for (const result of results) {
          for (const artifact of result.artifacts) {
            if (artifact.selectable !== false) seen.add(artifact.collector);
          }
        }
        return seen.size;
      },
      staleTime: 120_000,
    })),
  });

  return (
    <DocLayout>
      <DocPageHeader
        title="Documentation"
        description="Collector reference for each cloud provider — permissions, configuration, and output artifacts. Content is scaffolded and will expand over time."
      />
      <div className="px-6 py-8">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {DOC_PROVIDERS.map((provider, index) => (
            <DocProviderCard
              key={provider}
              provider={provider}
              collectorCount={counts[index]?.data}
              description={PROVIDER_INTROS[provider]}
            />
          ))}
        </div>
      </div>
    </DocLayout>
  );
}
