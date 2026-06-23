"use client";

import { fmtNum } from "@/lib/format";
import type { CloudTrailManagementCollection, CloudTrailCollection } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  Archive,
  Cloud,
  Database,
  FolderOpen,
  Info,
  CloudOff,
  Route,
  ScrollText,
} from "lucide-react";

export function CloudTrailCollectionSummary({ data }: { data: CloudTrailCollection }) {
  const trails = data.trails ?? [];
  const lookup = data.events?.lookup_api ?? { management: 0, insight: 0, total: 0 };
  const s3 = data.events?.s3 ?? { total: 0, by_bucket: [] };
  const buckets = s3.by_bucket ?? [];
  const logValidation = data.log_validation;
  const validationTrails = logValidation?.trails ?? [];
  const mgmt = data.management_collection;

  // Index validation results by trail ARN and name so each trail in the flow below can show
  // its integrity status inline (instead of a separate, bulky section).
  const validationByKey = new Map<string, (typeof validationTrails)[number]>();
  for (const v of validationTrails) {
    if (v.trail_arn) validationByKey.set(v.trail_arn, v);
    if (v.trail_name) validationByKey.set(v.trail_name, v);
  }

  // Index management-collection status (Collected / events / log objects) by trail.
  const mgmtTrails = mgmt?.trails ?? [];
  const mgmtByKey = new Map<string, (typeof mgmtTrails)[number]>();
  for (const t of mgmtTrails) {
    if (t.trail_arn) mgmtByKey.set(t.trail_arn, t);
    if (t.trail_name) mgmtByKey.set(t.trail_name, t);
  }

  // Index S3-event totals by destination bucket name.
  const bucketByName = new Map<string, (typeof buckets)[number]>();
  for (const b of buckets) bucketByName.set(b.bucket, b);

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
        />
        <SummaryStat icon={Archive} label="Trail events" value={fmtNum(s3.total)} />
        <SummaryStat
          icon={FolderOpen}
          label="S3 buckets"
          value={fmtNum(buckets.length || new Set(trails.map((t) => t.s3_bucket).filter(Boolean)).size)}
        />
      </div>

      {mgmt && (mgmt.trails_total > 0 || mgmt.fallback_reason === "no_s3_trail") && (
        <ManagementCollectionSection mgmt={mgmt} />
      )}

      {trails.length > 0 && (
        <section className="ct-resource-section">
          <h3 className="ct-resource-heading">
            <Route className="h-4 w-4" />
            Trails ({trails.length})
          </h3>
          {logValidation?.any_invalid && (
            <p className="text-xs text-danger">
              One or more trails failed digest/log validation, indicating possible tampering or gaps
              in the digest chain. Treat as a forensic finding.
            </p>
          )}
          <div className="grid gap-3">
            {trails.map((trail) => {
              const v =
                (trail.arn && validationByKey.get(trail.arn)) ||
                (trail.name && validationByKey.get(trail.name)) ||
                undefined;
              const m =
                (trail.arn && mgmtByKey.get(trail.arn)) ||
                (trail.name && mgmtByKey.get(trail.name)) ||
                undefined;
              const b = trail.s3_bucket ? bucketByName.get(trail.s3_bucket) : undefined;
              return (
              // Visual delivery mapping: trail → S3 bucket (arrow only when a bucket exists)
              <div key={trail.arn || trail.name} className="ct-flow">
                <div className="ct-flow-node">
                  <div className="ct-flow-node-label">
                    <Route className="h-3.5 w-3.5 shrink-0" />
                    Trail
                  </div>
                  <div className="ct-flow-node-value mono">{trail.name || "Unnamed trail"}</div>
                  {trail.arn && (
                    <div className="ct-flow-node-sub mono break-all">{trail.arn}</div>
                  )}
                  {trail.home_region && (
                    <div className="ct-flow-node-sub">{trail.home_region}</div>
                  )}
                  {(v || m) && (
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      {m && <TrailCollectStatus status={m.status} />}
                      {v && <ValidationStatusBadge status={v.status} />}
                    </div>
                  )}
                  {(v?.status === "valid" || v?.status === "invalid") && (
                    <div className="ct-flow-stats">
                      {v?.status === "valid" ? (
                        <>
                          <FlowStat
                            label="Digest files valid"
                            value={`${fmtNum(v.digest_valid ?? 0)}/${fmtNum(v.digest_total ?? 0)}`}
                          />
                          <FlowStat
                            label="Log files valid"
                            value={`${fmtNum(v.log_valid ?? 0)}/${fmtNum(v.log_total ?? 0)}`}
                          />
                        </>
                      ) : null}
                      {v?.status === "invalid" ? (
                        <>
                          <FlowStat
                            label="Digest files invalid"
                            value={`${fmtNum(v.digest_invalid ?? 0)}/${fmtNum(v.digest_total ?? 0)}`}
                          />
                          <FlowStat
                            label="Log files invalid"
                            value={`${fmtNum(v.log_invalid ?? 0)}/${fmtNum(v.log_total ?? 0)}`}
                          />
                        </>
                      ) : null}
                    </div>
                  )}
                  {v?.status === "error" && v.skip_reason && (
                    <div className="ct-flow-node-sub">{v.skip_reason}</div>
                  )}
                </div>

                {trail.s3_bucket ? (
                  <>
                    <div className="ct-flow-arrow" title="delivers logs to" aria-hidden="true">
                      <span className="ct-flow-arrow-line" />
                    </div>
                    <div className="ct-flow-node ct-flow-node--dest">
                      <div className="ct-flow-node-label">
                        <Archive className="h-3.5 w-3.5 shrink-0" />
                        S3 bucket
                      </div>
                      <div className="ct-flow-node-value mono break-all">{trail.s3_bucket}</div>
                      <div className="ct-flow-node-sub mono break-all">
                        {`arn:aws:s3:::${trail.s3_bucket}`}
                      </div>
                      {trail.s3_key_prefix && (
                        <div className="ct-flow-node-sub mono break-all">
                          prefix: {trail.s3_key_prefix}
                        </div>
                      )}
                      {b && (
                        <div className="ct-flow-stats">
                          <FlowStat label="Events from S3" value={fmtNum(b.events?.total ?? 0)} />
                          {b.events?.management ? (
                            <FlowStat
                              label="Management events"
                              value={fmtNum(b.events.management)}
                            />
                          ) : null}
                          {b.events?.data ? (
                            <FlowStat label="Data Events" value={fmtNum(b.events.data)} />
                          ) : null}
                          {b.events?.insight ? (
                            <FlowStat label="Insight events" value={fmtNum(b.events.insight)} />
                          ) : null}
                          {b.events?.network_activity ? (
                            <FlowStat
                              label="Network activity events"
                              value={fmtNum(b.events.network_activity)}
                            />
                          ) : null}
                          {b.objects_read != null && b.objects_read > 0 ? (
                            <FlowStat
                              label={b.truncated ? "Log objects read (truncated)" : "Log objects read"}
                              value={fmtNum(b.objects_read)}
                            />
                          ) : null}
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="ct-flow-empty">
                    <CloudOff className="h-3.5 w-3.5 shrink-0" />
                    No S3 delivery (Event History only)
                  </div>
                )}
              </div>
              );
            })}
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
            <div className="ct-flow-node-stats">
              <span>{fmtNum(lookup.management)} Management events</span>
              <span>{fmtNum(lookup.insight)} Insight events</span>
            </div>
          </article>
          <article className="ct-resource-block">
            <div className="flex items-center gap-2">
              <Archive className="h-4 w-4 text-accent" />
              <div className="ct-resource-block-title">Trail events</div>
            </div>
            <div className="mt-2 text-2xl font-semibold tabular-nums text-fg">
              {fmtNum(s3.total)}
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

function fallbackMessage(reason?: string): string {
  if (reason === "access_denied") return "Access to the trail S3 bucket(s) was denied.";
  if (reason === "no_logs")
    return "No log objects were found in the trail bucket(s) for this window.";
  if (reason === "no_s3_trail") return "No trail delivers logs to S3.";
  return "Trail S3 logs were unavailable.";
}

function TrailCollectStatus({ status }: { status: string }) {
  const label =
    status === "collected" ? "Collected" : status === "denied" ? "Access denied" : "No logs";
  return (
    <span className={cn("ct-resource-badge", status === "collected" ? "is-on" : "is-off")}>
      {label}
    </span>
  );
}

function ManagementCollectionSection({ mgmt }: { mgmt: CloudTrailManagementCollection }) {
  const collectedFromTrails = mgmt.mode === "trails";
  const noS3Trail = mgmt.fallback_reason === "no_s3_trail";

  // The per-trail collection status is now shown inline in the Trails flow above, so the
  // success summary ("All trails collected") is redundant. Only surface the fallback states.
  if (collectedFromTrails) return null;

  return (
    <section className="ct-resource-section">
      {noS3Trail ? (
        <>
          <h3 className="ct-resource-heading">
            <Info className="h-4 w-4 text-accent" />
            Collected from Event History
          </h3>
          <p className="mb-3 text-xs text-fg-subtle">
            No trail delivers logs to S3, so management events were collected from CloudTrail
            Event History (LookupEvents, ~90-day API lookback).
          </p>
        </>
      ) : (
        <>
          <h3 className="ct-resource-heading">
            <AlertTriangle className="h-4 w-4 text-warn-amber" />
            Trail collection failed, using Event History
          </h3>
          <p className="mb-3 text-xs text-warn-amber">
            {fallbackMessage(mgmt.fallback_reason)} Management events were collected from
            CloudTrail Event History (LookupEvents, ~90-day API lookback) instead.
          </p>
        </>
      )}
    </section>
  );
}

function ValidationStatusBadge({ status }: { status: string }) {
  const label =
    status === "valid"
      ? "Validated"
      : status === "invalid"
        ? "Integrity failure"
        : status === "error"
          ? "Validation error"
          : "Skipped";
  return (
    <span
      className={cn(
        "ct-resource-badge",
        status === "valid" && "is-on",
        status === "invalid" && "is-off",
        (status === "error" || status === "skipped") && "is-off",
      )}
    >
      {label}
    </span>
  );
}

function FlowStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="ct-flow-stat">
      <span className="ct-flow-stat-value">{value}</span>
      <span className="ct-flow-stat-label">{label}</span>
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
