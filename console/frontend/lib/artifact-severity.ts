/** Raw severity values from artifact YAML (distinct from event/findings severity). */
export type ArtifactSeverity = "critical" | "extended" | "high" | "medium" | "low" | "optional";

/** Display-only tiers shown in the Acquire UI. */
export type DisplayArtifactSeverity = "critical" | "high" | "medium";

export const ARTIFACT_SEVERITY_META: Record<
  DisplayArtifactSeverity,
  { label: string; className: string }
> = {
  critical: {
    label: "Critical",
    className: "border-critical/60 bg-[rgb(var(--error-bg))] text-critical",
  },
  high: {
    label: "High",
    className: "border-high/60 bg-[rgb(69,45,20)] text-high",
  },
  medium: {
    label: "Medium",
    className: "border-medium/60 bg-[rgb(55,45,15)] text-medium",
  },
};

export function normalizeArtifactSeverity(raw: string): string {
  return raw.trim().toLowerCase();
}

/** Map YAML severity to a display tier (Critical / High / Medium only). */
export function displayArtifactSeverity(raw: string): DisplayArtifactSeverity | null {
  switch (normalizeArtifactSeverity(raw)) {
    case "critical":
      return "critical";
    case "high":
    case "extended":
      return "high";
    case "medium":
    case "low":
      return "medium";
    default:
      return null;
  }
}

export function artifactSeverityMeta(raw: string) {
  const key = displayArtifactSeverity(raw);
  return key ? ARTIFACT_SEVERITY_META[key] : null;
}

export function artifactSeverityLabel(raw: string): string {
  const meta = artifactSeverityMeta(raw);
  return meta?.label ?? "";
}
