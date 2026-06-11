import type { UnifiedEvent } from "@/lib/types";

/** Human-readable label for the service that produced a finding. */
const ORIGIN_LABELS: Record<string, string> = {
  guardduty: "GuardDuty",
  securityhub: "Security Hub",
  macie: "Macie",
  detective: "Detective",
  inspector: "Inspector",
  inspector2: "Inspector",
  config: "AWS Config",
  iamaccessanalyzer: "IAM Access Analyzer",
  firewallmanager: "Firewall Manager",
  health: "AWS Health",
};

function titleCaseSlug(slug: string): string {
  return slug
    .split(/[-_]/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/** Resolve the originating product for a finding row in Security Findings. */
export function findingOrigin(event: UnifiedEvent): string {
  const provider = (event.event_provider || event.harbor_source || "").toLowerCase();
  if (ORIGIN_LABELS[provider]) return ORIGIN_LABELS[provider];

  if (event.harbor_source === "securityhub") {
    const raw = event.raw ?? {};
    const product =
      (raw.ProductName as string | undefined) ||
      ((raw.ProductFields as Record<string, string> | undefined)?.["aws/securityhub/ProductName"]);
    if (product) return product;
  }

  if (provider) return titleCaseSlug(provider);
  return titleCaseSlug(event.harbor_source || "unknown");
}

export function findingOriginClass(origin: string): string {
  const key = origin.toLowerCase().replace(/\s+/g, "");
  switch (key) {
    case "guardduty":
      return "finding-origin-guardduty";
    case "macie":
      return "finding-origin-macie";
    case "detective":
      return "finding-origin-detective";
    case "inspector":
    case "inspector2":
      return "finding-origin-inspector";
    case "securityhub":
      return "finding-origin-securityhub";
    default:
      return "finding-origin-other";
  }
}
