import type { UnifiedEvent } from "@/lib/types";

/** Human-readable label for a ventra_source / collector id. */
const ORIGIN_LABELS: Record<string, string> = {
  guardduty: "GuardDuty",
  securityhub: "Security Hub",
  macie: "Macie",
  detective: "Detective",
  inspector: "Inspector",
  inspector2: "Inspector",
  defender: "Defender for Cloud",
  config: "AWS Config",
  iamaccessanalyzer: "IAM Access Analyzer",
  firewallmanager: "Firewall Manager",
  health: "AWS Health",
};

export function ventraSourceLabel(source: string): string {
  const key = source.toLowerCase();
  return ORIGIN_LABELS[key] ?? titleCaseSlug(source);
}

function titleCaseSlug(slug: string): string {
  return slug
    .split(/[-_]/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/** Resolve the originating product for a finding row in Security Findings. */
export function findingOrigin(event: UnifiedEvent): string {
  const provider = (event.event_provider || event.ventra_source || "").toLowerCase();
  if (ORIGIN_LABELS[provider]) return ORIGIN_LABELS[provider];

  if (event.ventra_source === "securityhub") {
    const raw = event.raw ?? {};
    const product =
      (raw.ProductName as string | undefined) ||
      ((raw.ProductFields as Record<string, string> | undefined)?.["aws/securityhub/ProductName"]);
    if (product) return product;
  }

  if (provider) return titleCaseSlug(provider);
  return titleCaseSlug(event.ventra_source || "unknown");
}

