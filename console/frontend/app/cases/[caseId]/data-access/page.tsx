"use client";

import { useCase } from "@/components/case-context";
import { DataTable, type DataColumn } from "@/components/data-table";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Entity } from "@/components/pivot";
import { StatCard } from "@/components/stat";
import { Card, CardHeader, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtBytes, fmtNum } from "@/lib/format";
import type { DataAccessResponse } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Database, Download, FileSearch, Globe2, UserRound } from "lucide-react";

const SOURCE_LABEL: Record<string, string> = {
  s3_access: "S3 server access logs",
  cloudtrail: "CloudTrail data events",
};

// Operation classes, ordered by IR weight: destruction → modification → exfil → recon.
const OP_META: Record<string, { label: string; tone: string }> = {
  delete: { label: "Delete", tone: "bg-bad-red/80" },
  write: { label: "Write", tone: "bg-warn-amber/80" },
  read: { label: "Read", tone: "bg-accent/60" },
  list: { label: "List", tone: "bg-surface-3" },
  other: { label: "Other", tone: "bg-surface-3" },
};
const OP_ORDER = ["delete", "write", "read", "list", "other"];

type ObjectRow = DataAccessResponse["top_objects"][number];
type PrincipalRow = DataAccessResponse["top_principals"][number];
type IpRow = DataAccessResponse["top_ips"][number];

function ErrorCount({ value }: { value: number }) {
  return value > 0 ? (
    <span className="text-high">{fmtNum(value)}</span>
  ) : (
    <span className="text-fg-subtle">0</span>
  );
}

function OperationMix({ operations }: { operations: DataAccessResponse["operations"] }) {
  const total = operations.reduce((a, o) => a + o.count, 0) || 1;
  const sorted = [...operations].sort((a, b) => OP_ORDER.indexOf(a.op) - OP_ORDER.indexOf(b.op));
  return (
    <div className="p-4">
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface-2">
        {sorted.map((o) => (
          <div key={o.op} title={`${OP_META[o.op]?.label ?? o.op}: ${fmtNum(o.count)}`}
            className={OP_META[o.op]?.tone ?? "bg-surface-3"}
            style={{ width: `${(o.count / total) * 100}%` }} />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-3 text-2xs text-fg-subtle">
        {sorted.map((o) => (
          <span key={o.op} className="flex items-center gap-1.5">
            <span className={cn("h-2.5 w-2.5 rounded-sm", OP_META[o.op]?.tone)} />
            <span className={cn((o.op === "delete" || o.op === "write") && "text-fg")}>
              {OP_META[o.op]?.label ?? o.op}
            </span>
            <span className="mono text-fg">{fmtNum(o.count)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function DataAccessPage() {
  const { caseId } = useCase();
  const q = useQuery({ queryKey: ["data-access", caseId], queryFn: () => api.dataAccess(caseId) });

  if (q.isLoading || !q.data) return <LoadingPanel label="Loading data access…" />;
  const d = q.data;

  if (d.totals.events === 0) {
    return (
      <>
        <PanelHeader icon={Database} title="Data Access" panel="data-access" />
        <PanelBody>
          <Card className="py-4">
            <EmptyState
              icon={Database}
              title="No object-level access records in this case"
              description="S3 server access logging and CloudTrail S3 data events were not in scope for this window. Without them, object reads and writes cannot be attributed — this gap is recorded in the manifest."
            />
          </Card>
        </PanelBody>
      </>
    );
  }

  const objectCols: DataColumn<ObjectRow>[] = [
    {
      key: "resource_id", label: "Object", sortable: true, width: 520, min: 240, mono: true,
      wrap: true, value: (r) => r.resource_id,
    },
    { key: "count", label: "Accesses", align: "right", sortable: true, width: 100, mono: true,
      value: (r) => r.count, render: (r) => fmtNum(r.count) },
    { key: "bytes", label: "Bytes out", align: "right", sortable: true, width: 110, mono: true,
      value: (r) => r.bytes, render: (r) => (r.bytes > 0 ? fmtBytes(r.bytes) : "—") },
    { key: "ips", label: "IPs", align: "right", sortable: true, width: 80, mono: true,
      value: (r) => r.ips, render: (r) => fmtNum(r.ips) },
    { key: "failures", label: "Errors", align: "right", sortable: true, width: 90, mono: true,
      value: (r) => r.failures, render: (r) => <ErrorCount value={r.failures} /> },
  ];

  const principalCols: DataColumn<PrincipalRow>[] = [
    { key: "principal", label: "Principal", sortable: true, width: 320, min: 200,
      value: (r) => r.principal, render: (r) => <Entity kind="user" value={r.principal} truncate /> },
    { key: "count", label: "Accesses", align: "right", sortable: true, width: 100, mono: true,
      value: (r) => r.count, render: (r) => fmtNum(r.count) },
    { key: "bytes", label: "Bytes out", align: "right", sortable: true, width: 110, mono: true,
      value: (r) => r.bytes, render: (r) => (r.bytes > 0 ? fmtBytes(r.bytes) : "—") },
    { key: "failures", label: "Errors", align: "right", sortable: true, width: 90, mono: true,
      value: (r) => r.failures, render: (r) => <ErrorCount value={r.failures} /> },
  ];

  const ipCols: DataColumn<IpRow>[] = [
    {
      key: "source_ip", label: "Source IP", sortable: true, width: 200, min: 140,
      value: (r) => r.source_ip, render: (r) => <Entity kind="ip" value={r.source_ip} />,
    },
    { key: "count", label: "Accesses", align: "right", sortable: true, width: 100, mono: true,
      value: (r) => r.count, render: (r) => fmtNum(r.count) },
    { key: "bytes", label: "Bytes out", align: "right", sortable: true, width: 110, mono: true,
      value: (r) => r.bytes, render: (r) => (r.bytes > 0 ? fmtBytes(r.bytes) : "—") },
    { key: "failures", label: "Errors", align: "right", sortable: true, width: 90, mono: true,
      value: (r) => r.failures, render: (r) => <ErrorCount value={r.failures} /> },
  ];

  return (
    <>
      <PanelHeader
        icon={Database}
        title="Data Access"
        description="Who read or wrote which S3 object, from where — S3 server access logs paired with CloudTrail data events. Reads are the exfil lens; writes/deletes are destruction/ransomware."
        panel="data-access"
      />
      <PanelBody className="space-y-6">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatCard label="Access events" value={fmtNum(d.totals.events)} icon={Database} />
          <StatCard label="Objects touched" value={fmtNum(d.totals.objects)} icon={FileSearch} />
          <StatCard label="Bytes downloaded" value={fmtBytes(d.totals.bytes_out)} icon={Download}
            tone={d.totals.bytes_out > 0 ? "high" : "default"} />
          <StatCard label="Errors / denials" value={fmtNum(d.totals.failures)}
            tone={d.totals.failures > 0 ? "high" : "default"} />
        </div>

        <Card>
          <CardHeader
            title="Operation mix"
            subtitle="Reads = exfil · writes/deletes = destruction or ransomware"
            icon={UserRound}
            action={
              <span className="text-2xs text-fg-subtle">
                {d.by_source.map((s) => `${SOURCE_LABEL[s.source] ?? s.source}: ${fmtNum(s.count)}`).join(" · ")}
              </span>
            }
          />
          <OperationMix operations={d.operations} />
        </Card>

        <div className="cloudtrail-view">
          <Card className="overflow-hidden p-0">
            <CardHeader title="Most-accessed objects" subtitle="Sort by bytes for the largest exfil candidates"
              icon={FileSearch} className="px-4 py-3" />
            <DataTable
              columns={objectCols}
              rows={d.top_objects}
              getRowKey={(r) => r.resource_id}
              initialSort={{ key: "count", dir: "desc" }}
              filterPlaceholder="Filter objects…"
              emptyLabel="No objects match."
              pageSizeKey="ventra.data-access.objects.page-size"
            />
          </Card>
        </div>

        <div className="cloudtrail-view grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card className="overflow-hidden p-0">
            <CardHeader title="Top principals" subtitle={`${fmtNum(d.totals.principals)} distinct · who is touching the data`}
              icon={UserRound} className="px-4 py-3" />
            <DataTable
              columns={principalCols}
              rows={d.top_principals}
              getRowKey={(r) => r.principal}
              initialSort={{ key: "count", dir: "desc" }}
              filterPlaceholder="Filter principals…"
              emptyLabel="No principals match."
              pageSizeKey="ventra.data-access.principals.page-size"
            />
          </Card>

          <Card className="overflow-hidden p-0">
            <CardHeader title="Source IPs" subtitle="Where access originated" icon={Globe2} className="px-4 py-3" />
            <DataTable
              columns={ipCols}
              rows={d.top_ips}
              getRowKey={(r) => r.source_ip}
              initialSort={{ key: "count", dir: "desc" }}
              filterPlaceholder="Filter IPs…"
              emptyLabel="No source IPs match."
              pageSizeKey="ventra.data-access.ips.page-size"
            />
          </Card>
        </div>
      </PanelBody>
    </>
  );
}
