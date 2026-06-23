import { displayArtifactLabel } from "./artifact-icons";
import type { Artifact } from "./types";

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

export function paramKeys(schema: ParamSchema | undefined): string[] {
  if (!schema) return [];
  return Object.keys(schema);
}

export function requiredParamKeys(schema: ParamSchema | undefined): string[] {
  return paramKeys(schema).filter((k) => schema?.[k]?.required);
}

export function paramHint(schema: ParamSchema | undefined, key: string): string {
  const field = schema?.[key];
  if (field?.description) return String(field.description);
  if (field?.type) return String(field.type);
  return key;
}

export function missingRequiredParams(
  artifact: Artifact,
  values: Record<string, string> | undefined,
): string[] {
  const schema = artifact.parameters as ParamSchema | undefined;
  return requiredParamKeys(schema).filter((key) => !(values?.[key] ?? "").trim());
}

export function validateArtifactParams(
  artifacts: Artifact[],
  params: Record<string, Record<string, string>>,
): { ok: boolean; errors: ParamValidationError[] } {
  const errors: ParamValidationError[] = [];
  for (const artifact of artifacts) {
    for (const param of missingRequiredParams(artifact, params[artifact.collector])) {
      errors.push({
        collector: artifact.collector,
        label: displayArtifactLabel(artifact.collector),
        param,
        message: `Required parameter "${param}" is missing`,
      });
    }
  }
  return { ok: errors.length === 0, errors };
}
