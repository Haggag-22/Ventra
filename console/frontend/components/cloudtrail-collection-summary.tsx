"use client";

import { fmtNum } from "@/lib/format";
import type { CloudTrailCollection } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  Archive,
  Cloud,
  Database,
  FolderOpen,
  Route,
  ScrollText,
  Server,
} from "lucide-react";

function BoolBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={cn(
        "ct-resource-badge",
        ok ? "is-on" : "is-off",
      )}
    >
      {label}
    </span>
  );
}

export function CloudTrailCollectionSummary({ data }: { data: CloudTrailCollection }) {
  const trails = data.trails ?? [];
  const lookup = data.events?.lookup_api ?? { management: 0, insight: 0, total: 0 };
  const s3 = data.events?.s3 ?? { total: 0, by_bucket: [] };
  const buckets = s3.by_bucket ?? [];

  return (
    <div className="ct-collection-summary space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <SummaryStat
          icon={Route}
          label="Trails collected"
          value={fmtNum(data.trail_count ?? trails.length)}
        />
        <SummaryStat
          icon={Database}
          label="LookupEvents API"
          value={fmtNum(lookup.total)}
          sub={`${fmtNum(lookup.management)} mgmt · ${fmtNum(lookup.insight)} insight`}
        />
        <SummaryStat
          icon={Archive}
          label="S3 log files"
          value={fmtNum(s3.total)}
          sub={
            s3.data || s3.insight || s3.network_activity
              ? [
                  s3.data ? `${fmtNum(s3.data)} data` : null,
                  s3.insight ? `${fmtNum(s3.insight)} insight` : null,
                  s3.network_activity ? `${fmtNum(s3.network_activity)} network` : null,
                ]
                  .filter(Boolean)
                  .join(" · ")
              : undefined
          }
        />
        <SummaryStat
          icon={FolderOpen}
          label="S3 buckets"
          value={fmtNum(buckets.length || new Set(trails.map((t) => t.s3_bucket).filter(Boolean)).size)}
        />
      </div>

      {trails.length > 0 && (
        <section className="ct-resource-section">
          <h3 className="ct-resource-heading">
            <Route className="h-4 w-4" />
            Trails ({trails.length})
          </h3>
          <div className="grid gap-3 lg:grid-cols-2">
            {trails.map((trail) => (
              <article key={trail.arn || trail.name} className="ct-resource-block">
                <div className="ct-resource-block-title">{trail.name || "Unnamed trail"}</div>
                {trail.arn && (
                  <div className="mono ct-resource-meta break-all">{trail.arn}</div>
                )}
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <BoolBadge ok={trail.is_logging} label={trail.is_logging ? "Logging" : "Not logging"} />
                  {trail.is_multi_region && <span className="ct-resource-badge is-on">Multi-region</span>}
                  {trail.is_organization && (
                    <span className="ct-resource-badge is-on">Organization</span>
                  )}
                  {trail.log_file_validation && (
                    <span className="ct-resource-badge is-on">Log validation</span>
                  )}
                  {trail.data_events_configured && (
                    <span className="ct-resource-badge is-on">Data events</span>
                  )}
                  {trail.insight_events_configured && (
                    <span className="ct-resource-badge is-on">Insights</span>
                  )}
                  {trail.network_activity_configured && (
                    <span className="ct-resource-badge is-on">Network activity</span>
                  )}
                </div>
                {trail.s3_bucket && (
                  <div className="mt-3 border-t border-border pt-2">
                    <div className="flex items-center gap-1.5 text-2xs text-fg-subtle">
                      <Server className="h-3.5 w-3.5 shrink-0" />
                      S3 delivery
                    </div>
                    <div className="mono mt-1 text-xs text-fg">{trail.s3_bucket}</div>
                    {trail.s3_key_prefix && (
                      <div className="mono mt-0.5 text-2xs text-fg-subtle">
                        prefix: {trail.s3_key_prefix}
                      </div>
                    )}
                    {trail.home_region && (
                      <div className="mt-1 text-2xs text-fg-subtle">Home region: {trail.home_region}</div>
                    )}
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      {buckets.length > 0 && (
        <section className="ct-resource-section">
          <h3 className="ct-resource-heading">
            <Archive className="h-4 w-4" />
            S3 buckets — events collected
          </h3>
          <div className="grid gap-3 lg:grid-cols-2">
            {buckets.map((b) => (
              <article key={b.bucket} className="ct-resource-block">
                <div className="ct-resource-block-title">{b.bucket}</div>
                <div className="mt-1 text-2xl font-semibold tabular-nums text-fg">
                  {fmtNum(b.events?.total ?? 0)}
                  <span className="ml-1.5 text-xs font-normal text-fg-subtle">events from S3</span>
                </div>
                {(b.events?.data || b.events?.insight || b.events?.network_activity) && (
                  <div className="mt-1 text-2xs text-fg-subtle">
                    {[
                      b.events.data ? `${fmtNum(b.events.data)} data` : null,
                      b.events.insight ? `${fmtNum(b.events.insight)} insight` : null,
                      b.events.network_activity
                        ? `${fmtNum(b.events.network_activity)} network`
                        : null,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </div>
                )}
                {b.trail_arns?.length > 0 && (
                  <div className="mt-2 border-t border-border pt-2">
                    <div className="text-2xs text-fg-subtle">Linked trails</div>
                    <ul className="mt-1 space-y-0.5">
                      {b.trail_arns.map((arn) => (
                        <li key={arn} className="mono text-2xs text-fg-subtle break-all">
                          {arn}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {b.objects_read != null && b.objects_read > 0 && (
                  <div className="mt-1 text-2xs text-fg-subtle">
                    {fmtNum(b.objects_read)} log objects read
                    {b.truncated ? " (truncated)" : ""}
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="ct-resource-section">
        <h3 className="ct-resource-heading">
          <ScrollText className="h-4 w-4" />
          Event sources
        </h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <article className="ct-resource-block">
            <div className="flex items-center gap-2">
              <Cloud className="h-4 w-4 text-accent" />
              <div className="ct-resource-block-title">CloudTrail LookupEvents API</div>
            </div>
            <div className="mt-2 text-2xl font-semibold tabular-nums text-fg">
              {fmtNum(lookup.total)}
            </div>
            <div className="mt-1 text-xs text-fg-subtle">
              Portable management and insight events (~90-day API lookback).
            </div>
            <div className="mt-2 flex flex-wrap gap-2 text-2xs text-fg-subtle">
              <span>{fmtNum(lookup.management)} management</span>
              <span>·</span>
              <span>{fmtNum(lookup.insight)} insight</span>
            </div>
          </article>
          <article className="ct-resource-block">
            <div className="flex items-center gap-2">
              <Archive className="h-4 w-4 text-accent" />
              <div className="ct-resource-block-title">Trail S3 log files</div>
            </div>
            <div className="mt-2 text-2xl font-semibold tabular-nums text-fg">
              {fmtNum(s3.total)}
            </div>
            <div className="mt-1 text-xs text-fg-subtle">
              Data, insight, and network-activity events read from trail delivery buckets.
            </div>
            {buckets.length > 0 && (
              <div className="mt-2 text-2xs text-fg-subtle">
                Across {fmtNum(buckets.length)} bucket{buckets.length === 1 ? "" : "s"}
              </div>
            )}
          </article>
        </div>
      </section>
    </div>
  );
}

function SummaryStat({
  icon: Icon,
  label,
  value,
  sub,
}: {
  icon: typeof Route;
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="ct-resource-stat">
      <div className="flex items-center justify-between">
        <span className="stat-label">{label}</span>
        <Icon className="h-4 w-4 text-fg-subtle" />
      </div>
      <div className="mt-2 text-xl font-semibold tabular-nums text-fg">{value}</div>
      {sub && <div className="mt-0.5 text-2xs text-fg-subtle">{sub}</div>}
    </div>
  );
}
