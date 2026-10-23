import fs from "node:fs";
import path from "node:path";

/**
 * Params for `next export` (VENTRA_STATIC_EXPORT=1).
 * Case and run IDs stay on a `_` shell that FastAPI rewrites onto; pages read the real ID from
 * the browser URL with `useRouteParam` (plain `useParams()` returns "_" in the packaged console).
 * Collector doc pages are pre-rendered per artifact so the client router
 * matches the real URL. `_` remains so unknown collector ids still resolve.
 */

export const CASE_STATIC_PARAMS = [{ caseId: "_" }];
export const RUN_STATIC_PARAMS = [{ runId: "_" }];
export const DOCS_PROVIDER_PARAMS = [
  { provider: "aws" },
  { provider: "azure" },
  { provider: "gcp" },
  { provider: "kubernetes" },
];
/** Nested under [provider] — only the child segment key. */
export const DOCS_SECTION_PARAMS = [
  { section: "authentication" },
  { section: "permissions" },
  { section: "connections" },
  { section: "collectors" },
];

const ARTIFACT_CLOUDS = new Set(["aws", "azure", "gcp", "kubernetes"]);

function artifactsRoot(): string | null {
  const candidates = [
    path.resolve(process.cwd(), "..", "..", "artifacts"),
    path.resolve(process.cwd(), "artifacts"),
  ];
  return candidates.find((dir) => fs.existsSync(dir)) ?? null;
}

function collectYamlFiles(dir: string, out: string[]) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectYamlFiles(full, out);
    else if (entry.isFile() && (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml"))) {
      out.push(full);
    }
  }
}

function collectorIdsForCloud(cloud: string): string[] {
  const root = artifactsRoot();
  if (!root || !ARTIFACT_CLOUDS.has(cloud)) return [];
  const dir = path.join(root, cloud);
  if (!fs.existsSync(dir)) return [];
  const files: string[] = [];
  collectYamlFiles(dir, files);
  const ids = new Set<string>();
  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    const match = text.match(/^collector:\s*["']?([A-Za-z0-9_-]+)["']?\s*$/m);
    if (match) ids.add(match[1]);
  }
  return [...ids];
}

/** One static page per collector for this provider, plus the `_` fallback shell. */
export function docsCollectorStaticParams(provider: string | string[] | undefined): { collector: string }[] {
  const cloud = Array.isArray(provider) ? provider[0] : provider;
  const ids = new Set<string>(["_"]);
  if (cloud) {
    for (const id of collectorIdsForCloud(cloud)) ids.add(id);
  }
  return [...ids].sort().map((collector) => ({ collector }));
}
