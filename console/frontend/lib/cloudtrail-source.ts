import type { ParamValues } from "@/components/acquire-param-fields";

export type CloudTrailSourceMode = "lookup_events" | "bucket" | "trail";

export function cartNeedsCloudtrailSource(collectors: string[]): boolean {
  return collectors.includes("cloudtrail");
}

export function cloudtrailSourceMode(values: ParamValues | undefined): CloudTrailSourceMode | "" {
  const raw = typeof values?.collection_source === "string" ? values.collection_source.trim() : "";
  if (raw === "lookup_events" || raw === "bucket" || raw === "trail") return raw;
  return "";
}

export function cloudtrailList(values: ParamValues | undefined, key: string): string[] {
  const v = values?.[key];
  if (Array.isArray(v)) return v;
  if (typeof v === "string" && v.trim()) return [v];
  return [];
}

export function setCloudtrailSource(values: ParamValues, mode: CloudTrailSourceMode): ParamValues {
  const next: ParamValues = { ...values, collection_source: mode };
  if (mode !== "trail") {
    delete next.trail_arns;
    delete next.trail_names;
  }
  if (mode !== "bucket") {
    delete next.s3_bucket_names;
    delete next.s3_prefixes;
  }
  return next;
}

export function cloudtrailSourceError(
  values: ParamValues | undefined,
  required: boolean,
): string | null {
  if (!required) return null;
  const mode = cloudtrailSourceMode(values);
  if (!mode) return "Choose how CloudTrail events should be collected.";
  if (mode === "bucket" && !cloudtrailList(values, "s3_bucket_names").some((bucket) => bucket.trim())) {
    return "Enter at least one S3 bucket for CloudTrail.";
  }
  return null;
}
