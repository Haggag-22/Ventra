"use client";

import { fmtNum } from "@/lib/format";
import type {
  CloudTrailCollection,
  CloudTrailManagementTrail,
  CloudTrailTrailSummary,
} from "@/lib/types";
import { Archive, Cloud, Route } from "lucide-react";

type CollectionMode = "lookup" | "s3" | "mixed" | "none";

type EventCategoryCounts = {
  total: number;
  management: number;
  insight: number;
  data: number;
  network: number;
};

function eventCategoryCounts(data: CloudTrailCollection): EventCategoryCounts {
  const meta = data.meta ?? {};
  const lookup = data.events?.lookup_api ?? { management: 0, insight: 0, total: 0 };
  const s3 = data.events?.s3 ?? {};

  return {
    total: Number(meta.records ?? lookup.total + (s3.total ?? 0)),
    management: Number(meta.management_events ?? lookup.management + (s3.management ?? 0)),
    insight: Number(meta.insight_events ?? lookup.insight + (s3.insight ?? 0)),
    data: Number(meta.data_events ?? s3.data ?? 0),
    network: Number(meta.network_activity_events ?? s3.network_activity ?? 0),
  };
}

function resolveCollectionMode(data: CloudTrailCollection): CollectionMode {
  const lookupTotal = data.events?.lookup_api?.total ?? 0;
  const s3Total = data.events?.s3?.total ?? 0;
  const mgmt = data.management_collection;
  const metaSource = String(data.meta?.collection_source ?? "").toLowerCase();
  const mgmtSource = (data.management_source ?? "").toLowerCase();

  const explicitLookup =
    metaSource === "lookup_events" ||
    mgmtSource === "lookup_events" ||
    mgmt?.mode === "lookup_events" ||
    mgmt?.fallback_reason === "collection_source=lookup_events";

  if (explicitLookup) return "lookup";
  if (s3Total > 0 && lookupTotal > 0) return "mixed";
  if (s3Total > 0) return "s3";
  if (lookupTotal > 0) return "lookup";
  return "none";
}

export function CloudTrailCollectionSummary({ data }: { data: CloudTrailCollection }) {
  const lookup = data.events?.lookup_api ?? { management: 0, insight: 0, total: 0 };
  const s3 = data.events?.s3 ?? { total: 0, by_bucket: [] };
  const buckets = s3.by_bucket ?? [];
  const mgmt = data.management_collection;
  const mode = resolveCollectionMode(data);
  const counts = eventCategoryCounts(data);
  const showTrailInventory = mode === "s3" || mode === "mixed";

  const bucketByName = new Map(buckets.map((b) => [b.bucket, b]));
  const mgmtByKey = new Map<string, CloudTrailManagementTrail>();
  for (const t of mgmt?.trails ?? []) {
    if (t.trail_arn) mgmtByKey.set(t.trail_arn, t);
    if (t.trail_name) mgmtByKey.set(t.trail_name, t);
  }

  return (
    <div className="ct-collection-summary space-y-4">
      <CollectionSourceHeader
        mode={mode}
        counts={counts}
        lookup={lookup}
        s3={s3}
        mgmt={mgmt}
        bucketCount={buckets.length}
      />

      {showTrailInventory && (data.trails?.length ?? 0) > 0 && (
        <>
          <div className="border-t border-border" />
          <TrailS3Inventory
          trails={data.trails ?? []}
          bucketByName={bucketByName}
          mgmtByKey={mgmtByKey}
          logValidation={data.log_validation}
        />
        </>
      )}
    </div>
  );
}

function CollectionSourceHeader({
  mode,
  counts,
  lookup,
  s3,
  mgmt,
  bucketCount,
}: {
  mode: CollectionMode;
  counts: EventCategoryCounts;
  lookup: { management: number; insight: number; total: number };
  s3: {
    total: number;
    management?: number;
    data?: number;
    insight?: number;
    network_activity?: number;
  };
  mgmt?: CloudTrailCollection["management_collection"];
  bucketCount: number;
}) {
  if (mode === "lookup") {
    return (
      <section className="ct-source-header">
        <div className="flex items-start gap-3">
          <Cloud className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden />
          <div className="min-w-0 flex-1 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-fg">Collected from CloudTrail Event History</h3>
              <p className="mt-1 text-xs leading-relaxed text-fg-subtle">
                Events in this case came from the <span className="mono">LookupEvents</span> API
                (~90-day lookback). Trail configuration and S3 delivery buckets were not read for
                event data in this run.
              </p>
            </div>
            <EventCategoryMetrics counts={counts} />
          </div>
        </div>
      </section>
    );
  }

  if (mode === "s3") {
    const trailsCollected = mgmt?.trails_collected ?? 0;
    const bucketsRead = bucketsFromMgmt(mgmt) || bucketCount;
    return (
      <section className="ct-source-header">
        <div className="flex items-start gap-3">
          <Archive className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden />
          <div className="min-w-0 flex-1 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-fg">Collected from trail S3 log files</h3>
              <p className="mt-1 text-xs leading-relaxed text-fg-subtle">
                Events were read from CloudTrail log objects in the delivery buckets configured on
                your trails. This is the authoritative copy and can extend beyond the Event History
                API window.
              </p>
              <p className="mt-2 text-2xs text-fg-subtle">
                {fmtNum(trailsCollected)} trail{trailsCollected === 1 ? "" : "s"} read ·{" "}
                {fmtNum(bucketsRead)} bucket{bucketsRead === 1 ? "" : "s"} read
              </p>
            </div>
            <EventCategoryMetrics counts={counts} />
          </div>
        </div>
      </section>
    );
  }

  if (mode === "mixed") {
    return (
      <section className="ct-source-header space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-fg">Collected from two sources</h3>
          <p className="mt-1 text-xs leading-relaxed text-fg-subtle">
            Some events came from trail S3 logs; others were filled in from CloudTrail Event
            History when S3 collection was incomplete or unavailable.
          </p>
        </div>
        <EventCategoryMetrics counts={counts} />
        <div className="ct-source-metrics ct-source-metrics--2 border-t border-border pt-4">
          <div className="ct-source-metric">
            <div className="flex items-center gap-2 text-xs font-medium text-fg-subtle">
              <Archive className="h-3.5 w-3.5 text-accent" aria-hidden />
              Trail S3 logs
            </div>
            <div className="mt-1 text-xl font-semibold tabular-nums text-fg">{fmtNum(s3.total)}</div>
            <p className="mt-0.5 text-2xs text-fg-subtle">
              {fmtNum(mgmt?.trails_collected ?? 0)} trail
              {(mgmt?.trails_collected ?? 0) === 1 ? "" : "s"} ·{" "}
              {fmtNum(bucketsFromMgmt(mgmt) || bucketCount)} bucket
              {(bucketsFromMgmt(mgmt) || bucketCount) === 1 ? "" : "s"}
            </p>
          </div>
          <div className="ct-source-metric">
            <div className="flex items-center gap-2 text-xs font-medium text-fg-subtle">
              <Cloud className="h-3.5 w-3.5 text-accent" aria-hidden />
              Event History (LookupEvents)
            </div>
            <div className="mt-1 text-xl font-semibold tabular-nums text-fg">{fmtNum(lookup.total)}</div>
            <p className="mt-0.5 text-2xs text-fg-subtle">
              {fmtNum(lookup.management)} management · {fmtNum(lookup.insight)} insight
            </p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="ct-source-header">
      <p className="text-sm text-fg-subtle">No CloudTrail events were collected for this case.</p>
    </section>
  );
}

function EventCategoryMetrics({ counts }: { counts: EventCategoryCounts }) {
  return (
    <div className="ct-source-metrics ct-source-metrics--5">
      <SourceMetric label="Total events" value={fmtNum(counts.total)} />
      <SourceMetric label="Management events" value={fmtNum(counts.management)} />
      <SourceMetric label="Insight events" value={fmtNum(counts.insight)} />
      <SourceMetric label="Data events" value={fmtNum(counts.data)} />
      <SourceMetric label="Network events" value={fmtNum(counts.network)} />
    </div>
  );
}

function bucketsFromMgmt(mgmt?: CloudTrailCollection["management_collection"]): number {
  return mgmt?.buckets?.length ?? 0;
}

function SourceMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="ct-source-metric">
      <div className="ct-source-metric-label">{label}</div>
      <div className="ct-source-metric-value">{value}</div>
    </div>
  );
}

function TrailS3Inventory({
  trails,
  bucketByName,
  mgmtByKey,
  logValidation,
}: {
  trails: CloudTrailTrailSummary[];
  bucketByName: Map<string, NonNullable<CloudTrailCollection["events"]["s3"]["by_bucket"]>[number]>;
  mgmtByKey: Map<string, CloudTrailManagementTrail>;
  logValidation?: CloudTrailCollection["log_validation"];
}) {
  return (
    <section className="ct-resource-section">
      <h3 className="ct-resource-heading">
        <Route className="h-4 w-4" aria-hidden />
        Trails and buckets read
      </h3>
      {logValidation?.any_invalid && (
        <p className="text-xs text-danger">
          One or more trails failed digest or log validation. Treat as a possible integrity issue.
        </p>
      )}
      <div className="grid gap-3">
        {trails.map((trail) => {
          const m =
            (trail.arn && mgmtByKey.get(trail.arn)) ||
            (trail.name && mgmtByKey.get(trail.name)) ||
            undefined;
          const b = trail.s3_bucket ? bucketByName.get(trail.s3_bucket) : undefined;
          const validation = logValidation?.trails?.find(
            (v) => v.trail_arn === trail.arn || v.trail_name === trail.name,
          );

          return (
            <div key={trail.arn || trail.name} className="ct-flow">
              <div className="ct-flow-node">
                <div className="ct-flow-node-label">
                  <Route className="h-3.5 w-3.5 shrink-0" aria-hidden />
                  Trail
                </div>
                <div className="ct-flow-node-value mono">{trail.name || "Unnamed trail"}</div>
                {trail.home_region && <div className="ct-flow-node-sub">{trail.home_region}</div>}
                {m && (
                  <div className="ct-flow-node-sub">
                    {m.status === "collected"
                      ? `${fmtNum(m.records)} events · ${fmtNum(m.objects_read ?? 0)} log objects read`
                      : m.status === "denied"
                        ? "S3 access denied for this trail"
                        : "No log objects in window"}
                  </div>
                )}
                {validation?.status === "invalid" && (
                  <div className="ct-flow-node-sub text-danger">
                    Log integrity check failed ({fmtNum(validation.log_invalid ?? 0)} invalid files)
                  </div>
                )}
              </div>

              {trail.s3_bucket ? (
                <>
                  <div className="ct-flow-arrow" title="logs delivered to" aria-hidden="true">
                    <span className="ct-flow-arrow-line" />
                  </div>
                  <div className="ct-flow-node ct-flow-node--dest">
                    <div className="ct-flow-node-label">
                      <Archive className="h-3.5 w-3.5 shrink-0" aria-hidden />
                      S3 bucket
                    </div>
                    <div className="ct-flow-node-value mono break-all">{trail.s3_bucket}</div>
                    {b && (
                      <div className="ct-flow-node-sub">
                        {fmtNum(b.events?.total ?? 0)} events from this bucket
                        {b.objects_read ? ` · ${fmtNum(b.objects_read)} objects read` : ""}
                      </div>
                    )}
                  </div>
                </>
              ) : null}
            </div>
          );
        })}
      </div>
    </section>
  );
}
