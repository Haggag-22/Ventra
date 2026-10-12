import { displayArtifactLabel } from "./artifact-icons";
import { api } from "./api";
import { compareCollectorCategories, compareCollectorsByKind } from "./catalog";
import { artifactCloudsForProvider, type DocProvider } from "./docs-routes";
import type { Artifact } from "./types";

export type ArtifactCategoryGroup = {
  category: string;
  items: Artifact[];
};

/** Every collector for a provider, including ones Acquire hides because they run automatically. */
export async function loadDocArtifacts(provider: DocProvider): Promise<Artifact[]> {
  const clouds = artifactCloudsForProvider(provider);
  const results = await Promise.all(
    clouds.map((cloud) => api.artifacts(cloud, undefined, { includeImplicit: true })),
  );
  const byCollector = new Map<string, Artifact>();
  for (const result of results) {
    for (const artifact of result.artifacts) {
      if (!artifact.collector || byCollector.has(artifact.collector)) continue;
      byCollector.set(artifact.collector, artifact);
    }
  }
  return [...byCollector.values()];
}

/** Group artifacts by category using the Acquire catalog sort order. */
export function groupArtifactsByCategory(artifacts: Artifact[]): ArtifactCategoryGroup[] {
  const selectable = artifacts.filter((a) => a.collector);
  const groups = new Map<string, Artifact[]>();

  for (const artifact of selectable) {
    const key = artifact.category || "Other";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(artifact);
  }

  return [...groups.entries()]
    .sort(([a], [b]) => compareCollectorCategories(a, b))
    .map(([category, items]) => ({
      category,
      items: items.sort((a, b) =>
        compareCollectorsByKind(
          displayArtifactLabel(a.collector, a.cloud),
          displayArtifactLabel(b.collector, b.cloud),
        ),
      ),
    }));
}
