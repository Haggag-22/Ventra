"use client";

import { ParamFieldLabel } from "@/components/param-field-info";
import { Input } from "@/components/ui";
import type { ParamFieldDef } from "@/lib/collector-param-definitions";
import {
  pruneHiddenParamValues,
  visibleParamFields,
  type ParamValueMap,
} from "@/lib/collector-param-definitions";
import { cn } from "@/lib/utils";
import { Plus, X } from "lucide-react";

export type ParamValues = Record<string, string[] | boolean | string>;

/** Matches right-panel `.acquire-kit-input` — visible neutral borders. */
const PARAM_INPUT_CLASS = "acquire-kit-input";

const PARAM_ACTION_BTN = cn(
  "flex h-9 w-9 shrink-0 items-center justify-center rounded-md border",
  "bg-surface-2/60 text-fg-subtle transition-colors",
  "!border-border-strong/85 hover:!border-border-strong",
  "focus:outline-none focus-visible:ring-1 focus-visible:ring-accent/30",
);

function listValues(values: ParamValues, key: string): string[] {
  const v = values[key];
  if (Array.isArray(v)) return v;
  if (typeof v === "string" && v.trim()) return [v.trim()];
  return [];
}

function boolValue(values: ParamValues, key: string): boolean {
  const v = values[key];
  return v === true;
}

function stringValue(values: ParamValues, key: string): string {
  const v = values[key];
  return typeof v === "string" ? v : "";
}

export function AcquireParamFields({
  fields,
  values,
  onChange,
  className,
  compact = false,
}: {
  fields: ParamFieldDef[];
  values: ParamValues;
  onChange: (next: ParamValues) => void;
  className?: string;
  compact?: boolean;
}) {
  if (!fields.length) return null;

  const setList = (key: string, items: string[]) => {
    onChange({ ...values, [key]: items });
  };

  const setBool = (key: string, checked: boolean) => {
    onChange({ ...values, [key]: checked });
  };

  const setString = (key: string, val: string) => {
    let next = { ...values, [key]: val };
    if (key === "collection_source") {
      next = pruneHiddenParamValues(fields, next);
    }
    onChange(next);
  };

  const visibleFields = visibleParamFields(fields, values);

  if (!visibleFields.length) return null;

  return (
    <div
      className={cn(
        compact
          ? "grid gap-x-8 gap-y-5 sm:grid-cols-2"
          : "grid gap-x-8 gap-y-5 md:grid-cols-2 xl:grid-cols-3",
        className,
      )}
    >
      {visibleFields.map((field) => (
        <div key={field.key} className="min-w-0 space-y-2.5">
          <ParamFieldLabel
            label={field.label}
            required={field.required}
            description={field.description}
            docUrl={field.docUrl}
            compact={compact}
          />

          {field.type === "boolean" ? (
            <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
              <input
                type="checkbox"
                checked={boolValue(values, field.key)}
                onChange={(e) => setBool(field.key, e.target.checked)}
                className="rounded border-border"
              />
              Enable
            </label>
          ) : field.type === "select" ? (
            <select
              className={cn(PARAM_INPUT_CLASS, "w-full")}
              value={stringValue(values, field.key) || field.defaultValue || ""}
              onChange={(e) => setString(field.key, e.target.value)}
            >
              {(field.options ?? []).map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          ) : field.type === "string" ? (
            <Input
              className={cn(PARAM_INPUT_CLASS, "w-full")}
              placeholder={field.placeholder || `Enter ${field.label.toLowerCase()}…`}
              value={stringValue(values, field.key)}
              onChange={(e) => setString(field.key, e.target.value)}
            />
          ) : (
            <MultiValueInput
              items={listValues(values, field.key)}
              placeholder={field.placeholder || "Add value…"}
              onChange={(items) => setList(field.key, items)}
            />
          )}
        </div>
      ))}
    </div>
  );
}

export function MultiValueInput({
  items,
  placeholder,
  onChange,
  className,
}: {
  items: string[];
  placeholder: string;
  onChange: (items: string[]) => void;
  className?: string;
}) {
  const rows = items.length ? items : [""];

  return (
    <div className={cn("space-y-2", className)}>
      {rows.map((item, idx) => {
        const isLast = idx === rows.length - 1;
        const showRemove = rows.length > 1 || item.trim();

        return (
          <div key={idx} className="flex items-center gap-2">
            <Input
              className={cn(PARAM_INPUT_CLASS, "min-w-0 flex-1 mono")}
              placeholder={placeholder}
              value={item}
              onChange={(e) => {
                const next = [...rows];
                next[idx] = e.target.value;
                onChange(next.filter((v, i) => v.trim() || i === idx));
              }}
            />
            {isLast ? (
              <button
                type="button"
                aria-label="Add value"
                className={cn(
                  PARAM_ACTION_BTN,
                  "hover:border-accent hover:bg-accent/10 hover:text-accent",
                )}
                onClick={() => onChange([...rows.filter((r) => r.trim()), ""])}
              >
                <Plus className="h-4 w-4" />
              </button>
            ) : null}
            {showRemove ? (
              <button
                type="button"
                aria-label="Remove value"
                className={cn(
                  PARAM_ACTION_BTN,
                  "hover:border-bad-red/50 hover:bg-bad-red/10 hover:text-bad-red",
                )}
                onClick={() => {
                  const next = rows.filter((_, i) => i !== idx);
                  onChange(next.length ? next : []);
                }}
              >
                <X className="h-4 w-4" />
              </button>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

/** Serialize UI values for the acquisition build API. */
export function serializeParamValues(
  values: ParamValues,
  fields?: ParamFieldDef[],
): Record<string, unknown> {
  let scoped: ParamValueMap = { ...values };
  if (fields) {
    for (const field of fields) {
      if (
        field.type === "select" &&
        field.defaultValue &&
        (scoped[field.key] === undefined ||
          (typeof scoped[field.key] === "string" && !String(scoped[field.key]).trim()))
      ) {
        scoped[field.key] = field.defaultValue;
      }
    }
    scoped = pruneHiddenParamValues(fields, scoped);
  }
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(scoped)) {
    if (typeof val === "boolean") {
      if (val) out[key] = true;
      continue;
    }
    if (typeof val === "string") {
      const trimmed = val.trim();
      if (trimmed) out[key] = trimmed;
      continue;
    }
    if (Array.isArray(val)) {
      const cleaned = val.map((v) => v.trim()).filter(Boolean);
      if (cleaned.length === 1) out[key] = cleaned[0];
      else if (cleaned.length > 1) out[key] = cleaned;
    }
  }
  return out;
}
