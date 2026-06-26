import { displayArtifactLabel } from "./artifact-icons";
import {
  collectorParamSchema,
  type ParamFieldDef,
} from "./collector-param-definitions";
import type { Artifact } from "./types";
import type { ParamValues } from "@/components/acquire-param-fields";

export type ParamSchema = Record<
  string,
  { type?: string; required?: boolean; default?: unknown; description?: string }
>;

export type ParamValidationError = {
  collector: string;
  label: string;
  param: string;
  message: string;
};

/** Merge artifact YAML parameters with rich Acquire UI schemas. */
export function resolvedParamFields(artifact: Artifact): ParamFieldDef[] {
  const fromUi = collectorParamSchema(artifact.collector);
  if (fromUi.length) return fromUi;

  const schema = artifact.parameters as ParamSchema | undefined;
  return paramKeys(schema).map((key) => ({
    key,
    label: paramLabel(key),
    type: schema?.[key]?.type === "list" ? "list" : "string",
    description: schema?.[key]?.description ? String(schema[key].description) : undefined,
    required: schema?.[key]?.required,
    placeholder: paramPlaceholder(schema, key) || undefined,
  }));
}

export function paramKeys(schema: ParamSchema | undefined): string[] {
  if (!schema) return [];
  return Object.keys(schema);
}

export function requiredParamKeys(schema: ParamSchema | undefined): string[] {
  return paramKeys(schema).filter((k) => schema?.[k]?.required);
}

export function paramLabel(key: string): string {
  if (!key) return key;
  return key
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function paramHint(schema: ParamSchema | undefined, key: string): string {
  const field = schema?.[key];
  if (field?.description) return String(field.description);
  return "";
}

export function paramPlaceholder(schema: ParamSchema | undefined, key: string): string {
  const field = schema?.[key];
  if (field?.default != null && String(field.default).trim()) return String(field.default);
  return "";
}

function paramHasValue(values: ParamValues | undefined, field: ParamFieldDef): boolean {
  if (!values) return false;
  const v = values[field.key];
  if (field.type === "boolean") return v === true;
  if (typeof v === "string") return v.trim().length > 0;
  if (Array.isArray(v)) return v.some((item) => item.trim());
  return false;
}

export function missingRequiredParams(
  artifact: Artifact,
  values: ParamValues | undefined,
): string[] {
  return resolvedParamFields(artifact)
    .filter((f) => f.required)
    .filter((f) => !paramHasValue(values, f))
    .map((f) => f.key);
}

export function validateArtifactParams(
  artifacts: Artifact[],
  params: Record<string, ParamValues>,
): { ok: boolean; errors: ParamValidationError[] } {
  const errors: ParamValidationError[] = [];
  for (const artifact of artifacts) {
    for (const param of missingRequiredParams(artifact, params[artifact.collector])) {
      errors.push({
        collector: artifact.collector,
        label: displayArtifactLabel(artifact.collector),
        param,
        message: `Required parameter "${paramLabel(param)}" is missing`,
      });
    }
  }
  return { ok: errors.length === 0, errors };
}
