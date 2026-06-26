"use client";

import { ParamFieldLabel } from "@/components/param-field-info";
import { Button, Input } from "@/components/ui";
import type { ParamFieldDef } from "@/lib/collector-param-definitions";
import { cn } from "@/lib/utils";
import { Plus, X } from "lucide-react";

export type ParamValues = Record<string, string[] | boolean | string>;

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
    onChange({ ...values, [key]: val });
  };

  return (
    <div
      className={cn(
        compact ? "grid gap-3 sm:grid-cols-2" : "grid gap-4 md:grid-cols-2 xl:grid-cols-3",
        className,
      )}
    >
      {fields.map((field) => (
        <div
          key={field.key}
          className={cn(
            "rounded-lg border border-border/80 bg-surface-2/40",
            compact ? "p-2.5" : "p-3",
          )}
        >
          <div className={compact ? "mb-1.5" : "mb-2"}>
            <ParamFieldLabel
              label={field.label}
              required={field.required}
              description={field.description}
              docUrl={field.docUrl}
              compact={compact}
            />
          </div>

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
          ) : field.type === "string" ? (
            <Input
              className="h-9 text-sm"
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
      {rows.map((item, idx) => (
        <div key={idx} className="flex items-center gap-2">
          <Input
            className="h-9 flex-1 text-sm mono"
            placeholder={placeholder}
            value={item}
            onChange={(e) => {
              const next = [...rows];
              next[idx] = e.target.value;
              onChange(next.filter((v, i) => v.trim() || i === idx));
            }}
          />
          {rows.length > 1 || item.trim() ? (
            <button
              type="button"
              aria-label="Remove value"
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border text-fg-subtle hover:border-bad-red/50 hover:text-bad-red"
              onClick={() => {
                const next = rows.filter((_, i) => i !== idx);
                onChange(next.length ? next : []);
              }}
            >
              <X className="h-4 w-4" />
            </button>
          ) : null}
        </div>
      ))}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        icon={Plus}
        className="text-xs"
        onClick={() => onChange([...rows.filter((r) => r.trim()), ""])}
      >
        Add value
      </Button>
    </div>
  );
}

/** Serialize UI values for the acquisition build API. */
export function serializeParamValues(values: ParamValues): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(values)) {
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
