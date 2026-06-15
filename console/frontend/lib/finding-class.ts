import type { UnifiedEvent } from "@/lib/types";

// A finding's "class" describes what its raw payload represents: a compliance control result,
// a vulnerability, a threat detection, a sensitive-data hit, etc. This mirrors FINDING_CLASS_SQL
// in console/backend/app/store.py — keep the two in sync so the column matches the filter.
export type FindingClass =
  | "Compliance"
  | "Vulnerability"
  | "Threat"
  | "Sensitive data"
  | "Data exposure"
  | "Configuration"
  | "Other";

export const FINDING_CLASS_OPTIONS: FindingClass[] = [
  "Threat",
  "Vulnerability",
  "Compliance",
  "Sensitive data",
  "Data exposure",
  "Configuration",
  "Other",
];

function firstType(raw: Record<string, unknown>): string {
  const types = raw.Types;
  if (Array.isArray(types) && types.length > 0 && typeof types[0] === "string") {
    return types[0];
  }
  return "";
}

export function findingClass(event: UnifiedEvent): FindingClass {
  const source = (event.ventra_source || "").toLowerCase();
  const raw = (event.raw ?? {}) as Record<string, unknown>;
  const type0 = firstType(raw);
  const compliance = raw.Compliance as Record<string, unknown> | undefined;
  const pkgVuln = raw.packageVulnerabilityDetails as Record<string, unknown> | undefined;

  if (source === "inspector2" || pkgVuln?.vulnerabilityId) return "Vulnerability";

  if (
    compliance?.SecurityControlId ||
    type0.startsWith("Software and Configuration Checks/Industry and Regulatory Standards")
  ) {
    return "Compliance";
  }

  if (source === "macie" || type0.startsWith("Sensitive Data Identifications")) {
    return "Sensitive data";
  }

  if (type0.startsWith("Effects/Data Exposure")) return "Data exposure";

  if (
    source === "guardduty" ||
    raw.Type ||
    type0.startsWith("TTPs") ||
    type0.startsWith("Unusual Behaviors") ||
    type0.startsWith("Effects")
  ) {
    return "Threat";
  }

  if (type0.startsWith("Software and Configuration Checks")) return "Configuration";

  return "Other";
}

export function findingClassClass(cls: FindingClass): string {
  switch (cls) {
    case "Threat":
      return "finding-class-threat";
    case "Vulnerability":
      return "finding-class-vuln";
    case "Compliance":
      return "finding-class-compliance";
    case "Sensitive data":
    case "Data exposure":
      return "finding-class-data";
    case "Configuration":
      return "finding-class-config";
    default:
      return "finding-class-other";
  }
}
