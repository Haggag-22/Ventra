"use client";

import { MultiValueInput, type ParamValues } from "@/components/acquire-param-fields";
import {
  cloudtrailList,
  cloudtrailSourceMode,
  setCloudtrailSource,
  type CloudTrailSourceMode,
} from "@/lib/cloudtrail-source";
import { cn } from "@/lib/utils";
import { AlertTriangle } from "lucide-react";

const OPTIONS: {
  mode: CloudTrailSourceMode;
  label: string;
  summary: string;
  warning?: string;
}[] = [
  {
    mode: "lookup_events",
    label: "Lookup events (API)",
    summary: "Reads CloudTrail Event History with LookupEvents. No S3 access.",
    warning: "About 90 days of events. LookupEvents is rate limited and is slower than the S3 archive.",
  },
  {
    mode: "bucket",
    label: "S3 bucket",
    summary: "Reads CloudTrail log files from the buckets you name.",
  },
  {
    mode: "trail",
    label: "Trail",
    summary: "Discovers trails and reads the S3 buckets they deliver to. Name a trail to narrow that.",
  },
];

type Props = {
  values: ParamValues;
  onChange: (next: ParamValues) => void;
  required?: boolean;
};

export function CloudTrailSourceFields({ values, onChange, required = false }: Props) {
  const mode = cloudtrailSourceMode(values);
  const setList = (key: string, items: string[]) => onChange({ ...values, [key]: items });

  return (
    <div className="mb-5 rounded-lg border border-border bg-surface p-4">
      <div className="mb-3">
        <h3 className="text-base font-semibold text-fg">
          CloudTrail source
          {required && <span className="ml-1 text-bad-red">*</span>}
        </h3>
        <p className="mt-1 text-sm text-fg">
          Choose where CloudTrail events are read from.
        </p>
      </div>

      <div className="space-y-2">
        {OPTIONS.map((opt) => {
          const selected = mode === opt.mode;
          return (
            <div
              key={opt.mode}
              className={cn(
                "rounded-md border border-border bg-surface-2",
                selected && "border-l-2 border-l-[#FF9900]",
              )}
            >
              <label className="flex cursor-pointer gap-3 px-3 py-3">
                <input
                  type="radio"
                  name="cloudtrail_collection_source"
                  checked={selected}
                  onChange={() => onChange(setCloudtrailSource(values, opt.mode))}
                  className="mt-1 shrink-0"
                />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-semibold text-fg">{opt.label}</span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-fg">{opt.summary}</span>
                  {selected && opt.warning && (
                    <span className="mt-2 flex items-start gap-1.5 text-xs text-warn-amber">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      {opt.warning}
                    </span>
                  )}
                </span>
              </label>

              {selected && opt.mode === "bucket" && (
                <div className="space-y-3 border-t border-border/50 px-3 pb-3 pt-3">
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">S3 bucket names</span>
                    <MultiValueInput
                      items={cloudtrailList(values, "s3_bucket_names")}
                      placeholder="cloudtrail-logs-123456789012"
                      onChange={(items) => setList("s3_bucket_names", items)}
                    />
                  </label>
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">S3 prefixes (optional)</span>
                    <MultiValueInput
                      items={cloudtrailList(values, "s3_prefixes")}
                      placeholder="AWSLogs/123456789012/CloudTrail/"
                      onChange={(items) => setList("s3_prefixes", items)}
                    />
                  </label>
                </div>
              )}

              {selected && opt.mode === "trail" && (
                <div className="space-y-3 border-t border-border/50 px-3 pb-3 pt-3">
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">Trail ARNs (optional)</span>
                    <MultiValueInput
                      items={cloudtrailList(values, "trail_arns")}
                      placeholder="arn:aws:cloudtrail:us-east-1:123456789012:trail/management"
                      onChange={(items) => setList("trail_arns", items)}
                    />
                  </label>
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">Trail names (optional)</span>
                    <MultiValueInput
                      items={cloudtrailList(values, "trail_names")}
                      placeholder="management-trail"
                      onChange={(items) => setList("trail_names", items)}
                    />
                  </label>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
