"use client";

import { fmtNum } from "@/lib/format";
import type { CloudTrailManagementCollection, CloudTrailCollection } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  Archive,
  ArrowRight,
  CheckCircle2,
  Cloud,
  Database,
  FolderOpen,
  Info,
  CloudOff,
  Route,
  ScrollText,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";

export function CloudTrailCollectionSummary({ data }: { data: CloudTrailCollection }) {
  const trails = data.trails ?? [];
  const lookup = data.events?.lookup_api ?? { management: 0, insight: 0, total: 0 };
  const s3 = data.events?.s3 ?? { total: 0, by_bucket: [] };
  const buckets = s3.by_bucket ?? [];
  const logValidation = data.log_validation;
  const validationTrails = logValidation?.trails ?? [];
  const mgmt = data.management_collection;

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
            s3.management || s3.data || s3.insight || s3.network_activity
              ? [
                  s3.management ? `${fmtNum(s3.management)} mgmt` : null,
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

      {mgmt && (mgmt.trails_total > 0 || mgmt.fallback_reason === "no_s3_trail") && (
        <ManagementCollectionSection mgmt={mgmt} />
      )}

      {validationTrails.length > 0 && (
        <section className="ct-resource-section">
          <h3 className="ct-resource-heading">
            {logValidation?.any_invalid ? (
              <ShieldAlert className="h-4 w-4 text-danger" />
            ) : (
              <ShieldCheck className="h-4 w-4 text-success" />
            )}
            S3 log integrity (validate-logs)
          </h3>
          {logValidation?.any_invalid && (
            <p className="mb-3 text-xs text-danger">
              One or more trails failed digest/log validation — possible tampering or gaps in the
              digest chain. Treat as a forensic finding.
            </p>
          )}
          <div className="grid gap-3 lg:grid-cols-2">
            {validationTrails.map((v) => (
              <article key={v.trail_arn || v.trail_name} className="ct-resource-block">
                <div className="ct-resource-block-title">{v.trail_name}</div>
                <div className="mt-2">
                  <ValidationStatusBadge status={v.status} />
                </div>
                {v.status === "valid" && (
                  <div className="mt-2 text-xs text-fg-subtle">
                    {fmtNum(v.digest_valid ?? 0)}/{fmtNum(v.digest_total ?? 0)} digest files ·{" "}
                    {fmtNum(v.log_valid ?? 0)}/{fmtNum(v.log_total ?? 0)} log files valid
                  </div>
                )}
                {v.status === "invalid" && (
                  <div className="mt-2 space-y-1 text-xs text-danger">
                    {(v.digest_invalid ?? 0) > 0 && (
                      <div>
                        {fmtNum(v.digest_invalid)}/{fmtNum(v.digest_total ?? 0)} digest files
                        INVALID
                      </div>
                    )}
                    {(v.log_invalid ?? 0) > 0 && (
                      <div>
                        {fmtNum(v.log_invalid)}/{fmtNum(v.log_total ?? 0)} log files INVALID
                      </div>
                    )}
                    {v.invalid_details?.slice(0, 3).map((line) => (
                      <div key={line} className="mono text-2xs break-all opacity-90">
                        {line}
                      </div>
                    ))}
                  </div>
                )}
                {v.status === "error" && v.skip_reason && (
                  <div className="mt-2 text-xs text-fg-subtle">{v.skip_reason}</div>
                )}
              </article>
            ))}
          </div>
          <p className="mt-3 text-2xs text-fg-subtle">
            LookupEvents records are API-sourced and not covered by S3 digest validation.
          </p>
        </section>
      )}

      {trails.length > 0 && (
        <section className="ct-resource-section">
          <h3 className="ct-resource-heading">
            <Route className="h-4 w-4" />
            Trails ({trails.length})
          </h3>
          <div className="grid gap-3">
            {trails.map((trail) => (
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
                </div>

                {trail.s3_bucket ? (
                  <>
                    <div className="ct-flow-arrow" title="delivers logs to">
                      <ArrowRight className="h-4 w-4" />
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
                    </div>
                  </>
                ) : (
                  <div className="ct-flow-empty">
                    <CloudOff className="h-3.5 w-3.5 shrink-0" />
                    No S3 delivery · Event History only
                  </div>
                )}
              </div>
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
                {(b.events?.management ||
                  b.events?.data ||
                  b.events?.insight ||
                  b.events?.network_activity) && (
                  <div className="mt-1 text-2xs text-fg-subtle">
                    {[
                      b.events.management ? `${fmtNum(b.events.management)} mgmt` : null,
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
              {data.management_source === "s3_logs"
                ? "Fallback path only — management events were read from S3 logs for this case."
                : "Portable management and insight events (~90-day API lookback)."}
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
              {s3.management
                ? "Management, data, insight, and network-activity events read from trail delivery buckets."
                : "Data, insight, and network-activity events read from trail delivery buckets."}
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

function trailReasonLabel(reason?: string): string {
  if (reason === "access_denied") return "Access denied to bucket";
  if (reason === "no_logs_in_window") return "No log objects in window";
  return "Not collected";
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

  return (
    <section className="ct-resource-section">
      {collectedFromTrails ? (
        <>
          <h3 className="ct-resource-heading">
            <CheckCircle2 className="h-4 w-4 text-ok-green" />
            {mgmt.trails_collected >= mgmt.trails_total
              ? "All trails collected"
              : "Collected from trails"}
          </h3>
          <p className="mb-3 text-xs text-fg-subtle">
            Management events were read straight from{" "}
            <span className="font-medium text-fg">{fmtNum(mgmt.trails_collected)}</span> of{" "}
            {fmtNum(mgmt.trails_total)} trail{mgmt.trails_total === 1 ? "" : "s"} across{" "}
            {fmtNum(mgmt.buckets.length)} bucket{mgmt.buckets.length === 1 ? "" : "s"} — the
            authoritative log files. CloudTrail Event History was not needed.
          </p>
        </>
      ) : noS3Trail ? (
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
            Trail collection failed — using Event History
          </h3>
          <p className="mb-3 text-xs text-warn-amber">
            {fallbackMessage(mgmt.fallback_reason)} Management events were collected from
            CloudTrail Event History (LookupEvents, ~90-day API lookback) instead.
          </p>
        </>
      )}

      {mgmt.trails.length > 0 && (
        <div className="grid gap-3 lg:grid-cols-2">
          {mgmt.trails.map((t) => (
            <article key={t.trail_arn || t.trail_name} className="ct-resource-block">
              <div className="flex items-center justify-between gap-2">
                <div className="ct-resource-block-title">{t.trail_name || "Unnamed trail"}</div>
                <TrailCollectStatus status={t.status} />
              </div>
              {t.bucket && <div className="mono ct-resource-meta break-all">{t.bucket}</div>}
              <div className="mt-2 text-2xs text-fg-subtle">
                {t.status === "collected"
                  ? `${fmtNum(t.records)} events · ${fmtNum(t.objects_read ?? 0)} log objects`
                  : trailReasonLabel(t.reason)}
              </div>
            </article>
          ))}
        </div>
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
