"use client";

import { fmtNum } from "@/lib/format";
import type { VpcFlowCollection, VpcFlowLogSummary } from "@/lib/types";
import { Archive, Cloud, Network } from "lucide-react";

type CollectionMode = "s3" | "cloudwatch" | "mixed" | "none";

function collectionMode(data: VpcFlowCollection): CollectionMode {
  const s3 = data.s3_records > 0 || hasDest(data, "s3");
  const cw = data.cloudwatch_records > 0 || hasDest(data, "cloud-watch-logs");
  if (s3 && cw) return "mixed";
  if (s3) return "s3";
  if (cw) return "cloudwatch";
  return "none";
}

function hasDest(data: VpcFlowCollection, type: string): boolean {
  return (data.flow_logs ?? []).some((fl) => fl.destination_type === type);
}

function destKind(type: string): { label: string; Icon: typeof Archive } {
  if (type === "s3") return { label: "S3 bucket", Icon: Archive };
  if (type === "cloud-watch-logs") return { label: "CloudWatch log group", Icon: Cloud };
  return { label: type || "Destination", Icon: Archive };
}

function vpcLabel(fl: VpcFlowLogSummary): string {
  if (fl.vpc_name && fl.vpc_id && fl.vpc_name !== fl.vpc_id) {
    return `${fl.vpc_id} (${fl.vpc_name})`;
  }
  return fl.vpc_id || fl.resource_id || fl.flow_log_id || "—";
}

function uniqueDestinations(logs: VpcFlowLogSummary[], type: string): number {
  return new Set(
    logs.filter((fl) => fl.destination_type === type).map((fl) => fl.destination).filter(Boolean),
  ).size;
}

export function VpcFlowCollectionSummary({ data }: { data: VpcFlowCollection }) {
  const mode = collectionMode(data);
  const logs = data.flow_logs ?? [];
  const uncovered = data.vpcs_without_flow_logs ?? [];
  const objectsRead = Number(data.meta?.s3_objects_read ?? 0);

  return (
    <div className="ct-collection-summary space-y-4">
      <CollectionSourceHeader
        mode={mode}
        data={data}
        s3DestCount={uniqueDestinations(logs, "s3")}
        cwDestCount={uniqueDestinations(logs, "cloud-watch-logs")}
        objectsRead={objectsRead}
      />

      {logs.length > 0 && (
        <>
          <div className="border-t border-border" />
          <section className="ct-resource-section">
            <h3 className="ct-resource-heading">
              <Network className="h-4 w-4" aria-hidden />
              Flow logs and destinations
            </h3>
            <div className="grid gap-3">
              {logs.map((fl) => {
                const dest = destKind(fl.destination_type);
                const DestIcon = dest.Icon;
                return (
                  <div key={fl.flow_log_id || `${fl.resource_id}:${fl.destination}`} className="ct-flow">
                    <div className="ct-flow-node">
                      <div className="ct-flow-node-label">
                        <Network className="h-3.5 w-3.5 shrink-0" aria-hidden />
                        VPC
                      </div>
                      <div className="ct-flow-node-value mono">{vpcLabel(fl)}</div>
                      {fl.region && <div className="ct-flow-node-sub">{fl.region}</div>}
                      {fl.flow_log_id && (
                        <div className="ct-flow-node-sub mono">{fl.flow_log_id}</div>
                      )}
                      {fl.status && fl.status !== "ACTIVE" && (
                        <div className="ct-flow-node-sub">{fl.status}</div>
                      )}
                    </div>
                    {fl.destination ? (
                      <>
                        <div className="ct-flow-arrow" title="logs delivered to" aria-hidden="true">
                          <span className="ct-flow-arrow-line" />
                        </div>
                        <div className="ct-flow-node ct-flow-node--dest">
                          <div className="ct-flow-node-label">
                            <DestIcon className="h-3.5 w-3.5 shrink-0" aria-hidden />
                            {dest.label}
                          </div>
                          <div className="ct-flow-node-value mono break-all">{fl.destination}</div>
                          {fl.destination_type === "s3" && fl.prefix ? (
                            <div className="ct-flow-node-sub mono break-all">{fl.prefix}</div>
                          ) : null}
                          {fl.destination_type === "s3" && objectsRead > 0 && (
                            <div className="ct-flow-node-sub">
                              {fmtNum(data.s3_records)} flows · {fmtNum(objectsRead)} log objects read
                            </div>
                          )}
                          {fl.destination_type === "cloud-watch-logs" && data.cloudwatch_records > 0 && (
                            <div className="ct-flow-node-sub">
                              {fmtNum(data.cloudwatch_records)} flows from this log group
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
        </>
      )}

      {uncovered.length > 0 && (
        <p className="text-xs text-fg-subtle">
          {fmtNum(uncovered.length)} VPC{uncovered.length === 1 ? "" : "s"} without a VPC-level
          flow log: {uncovered.map((v) => v.name || v.id).join(", ")}
        </p>
      )}
    </div>
  );
}

function CollectionSourceHeader({
  mode,
  data,
  s3DestCount,
  cwDestCount,
  objectsRead,
}: {
  mode: CollectionMode;
  data: VpcFlowCollection;
  s3DestCount: number;
  cwDestCount: number;
  objectsRead: number;
}) {
  if (mode === "s3") {
    return (
      <section className="ct-source-header">
        <div className="flex items-start gap-3">
          <Archive className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden />
          <div className="min-w-0 flex-1 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-fg">Collected from S3 flow log files</h3>
              <p className="mt-1 text-xs leading-relaxed text-fg-subtle">
                Flow records were read from the S3 buckets configured as VPC Flow Log
                destinations. This is the delivery copy written by AWS, not a live API sample.
              </p>
              <p className="mt-2 text-2xs text-fg-subtle">
                {fmtNum(data.flow_log_count)} flow log{data.flow_log_count === 1 ? "" : "s"} ·{" "}
                {fmtNum(s3DestCount)} bucket{s3DestCount === 1 ? "" : "s"} read
                {objectsRead > 0 ? ` · ${fmtNum(objectsRead)} log objects` : ""}
              </p>
            </div>
            <FlowMetrics data={data} />
          </div>
        </div>
      </section>
    );
  }

  if (mode === "cloudwatch") {
    return (
      <section className="ct-source-header">
        <div className="flex items-start gap-3">
          <Cloud className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden />
          <div className="min-w-0 flex-1 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-fg">Collected from CloudWatch Logs</h3>
              <p className="mt-1 text-xs leading-relaxed text-fg-subtle">
                Flow records were read from CloudWatch log groups configured as VPC Flow Log
                destinations.
              </p>
              <p className="mt-2 text-2xs text-fg-subtle">
                {fmtNum(data.flow_log_count)} flow log{data.flow_log_count === 1 ? "" : "s"} ·{" "}
                {fmtNum(cwDestCount)} log group{cwDestCount === 1 ? "" : "s"} read
              </p>
            </div>
            <FlowMetrics data={data} />
          </div>
        </div>
      </section>
    );
  }

  if (mode === "mixed") {
    return (
      <section className="ct-source-header space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-fg">Collected from two destinations</h3>
          <p className="mt-1 text-xs leading-relaxed text-fg-subtle">
            Some flow records came from S3 delivery buckets; others were read from CloudWatch
            log groups.
          </p>
        </div>
        <FlowMetrics data={data} />
        <div className="ct-source-metrics ct-source-metrics--2 border-t border-border pt-4">
          <div className="ct-source-metric">
            <div className="flex items-center gap-2 text-xs font-medium text-fg-subtle">
              <Archive className="h-3.5 w-3.5 text-accent" aria-hidden />
              S3 flow log files
            </div>
            <div className="mt-1 text-xl font-semibold tabular-nums text-fg">
              {fmtNum(data.s3_records)}
            </div>
            <p className="mt-0.5 text-2xs text-fg-subtle">
              {fmtNum(s3DestCount)} bucket{s3DestCount === 1 ? "" : "s"}
              {objectsRead > 0 ? ` · ${fmtNum(objectsRead)} objects` : ""}
            </p>
          </div>
          <div className="ct-source-metric">
            <div className="flex items-center gap-2 text-xs font-medium text-fg-subtle">
              <Cloud className="h-3.5 w-3.5 text-accent" aria-hidden />
              CloudWatch Logs
            </div>
            <div className="mt-1 text-xl font-semibold tabular-nums text-fg">
              {fmtNum(data.cloudwatch_records)}
            </div>
            <p className="mt-0.5 text-2xs text-fg-subtle">
              {fmtNum(cwDestCount)} log group{cwDestCount === 1 ? "" : "s"}
            </p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="ct-source-header">
      <p className="text-sm text-fg-subtle">
        No VPC Flow Log destinations were recorded for this case.
      </p>
    </section>
  );
}

function FlowMetrics({ data }: { data: VpcFlowCollection }) {
  return (
    <div className="ct-source-metrics">
      <SourceMetric label="Total flows" value={fmtNum(data.records)} />
      <SourceMetric label="From S3" value={fmtNum(data.s3_records)} />
      <SourceMetric label="From CloudWatch" value={fmtNum(data.cloudwatch_records)} />
    </div>
  );
}

function SourceMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="ct-source-metric">
      <div className="ct-source-metric-label">{label}</div>
      <div className="ct-source-metric-value">{value}</div>
    </div>
  );
}
