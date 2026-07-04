import { compareCollectorCategories } from "./catalog";
import type { Artifact } from "./types";

export type ArtifactCategoryGroup = {
  category: string;
  items: Artifact[];
};

/** Group selectable artifacts by category using the Acquire catalog sort order. */
export function groupArtifactsByCategory(artifacts: Artifact[]): ArtifactCategoryGroup[] {
  const selectable = artifacts.filter((a) => a.selectable !== false);
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
      items: items.sort((a, b) => a.name.localeCompare(b.name)),
    }));
}
