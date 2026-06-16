"use client";

import { useCase } from "@/components/case-context";
import { DataTable, type DataColumn } from "@/components/data-table";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Entity } from "@/components/pivot";
import { StatCard } from "@/components/stat";
import { Card, CardHeader, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtNum } from "@/lib/format";
import type { DataAccessResponse } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { Database, FileSearch, Globe2, UserRound } from "lucide-react";

const SOURCE_LABEL: Record<string, string> = {
  s3_access: "S3 server access logs",
  cloudtrail: "CloudTrail data events",
};

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

export default function DataAccessPage() {
  const { caseId } = useCase();
  const q = useQuery({
    queryKey: ["data-access", caseId],
    queryFn: () => api.dataAccess(caseId),
  });

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
      key: "resource_id",
      label: "Object",
      sortable: true,
      width: 560,
      min: 240,
      mono: true,
      wrap: true,
      value: (r) => r.resource_id,
    },
    {
      key: "count",
      label: "Accesses",
      align: "right",
      sortable: true,
      width: 110,
      mono: true,
      value: (r) => r.count,
      render: (r) => fmtNum(r.count),
    },
    {
      key: "ips",
      label: "Distinct IPs",
      align: "right",
      sortable: true,
      width: 110,
      mono: true,
      value: (r) => r.ips,
      render: (r) => fmtNum(r.ips),
    },
    {
      key: "failures",
      label: "Errors",
      align: "right",
      sortable: true,
      width: 90,
      mono: true,
      value: (r) => r.failures,
      render: (r) => <ErrorCount value={r.failures} />,
    },
  ];

  const principalCols: DataColumn<PrincipalRow>[] = [
    {
      key: "principal",
      label: "Principal",
      sortable: true,
      width: 360,
      min: 200,
      value: (r) => r.principal,
      render: (r) => <Entity kind="user" value={r.principal} truncate />,
    },
    {
      key: "count",
      label: "Accesses",
      align: "right",
      sortable: true,
      width: 110,
      mono: true,
      value: (r) => r.count,
      render: (r) => fmtNum(r.count),
    },
    {
      key: "failures",
      label: "Errors",
      align: "right",
      sortable: true,
      width: 90,
      mono: true,
      value: (r) => r.failures,
      render: (r) => <ErrorCount value={r.failures} />,
    },
  ];

  const ipCols: DataColumn<IpRow>[] = [
    {
      key: "source_ip",
      label: "Source IP",
      sortable: true,
      width: 220,
      min: 140,
      value: (r) => r.source_ip,
      render: (r) => <Entity kind="ip" value={r.source_ip} />,
    },
    {
      key: "count",
      label: "Accesses",
      align: "right",
      sortable: true,
      width: 110,
      mono: true,
      value: (r) => r.count,
      render: (r) => fmtNum(r.count),
    },
    {
      key: "failures",
      label: "Errors",
      align: "right",
      sortable: true,
      width: 90,
      mono: true,
      value: (r) => r.failures,
      render: (r) => <ErrorCount value={r.failures} />,
    },
  ];

  return (
    <>
      <PanelHeader
        icon={Database}
        title="Data Access"
        description="Who read or wrote which S3 object, from where — S3 server access logs paired with CloudTrail S3 data events. The 'what data was touched' lens."
        panel="data-access"
      />
      <PanelBody className="space-y-6">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatCard label="Access events" value={fmtNum(d.totals.events)} icon={Database} />
          <StatCard label="Objects touched" value={fmtNum(d.totals.objects)} icon={FileSearch} />
          <StatCard label="Principals" value={fmtNum(d.totals.principals)} icon={UserRound} />
          <StatCard
            label="Errors / denials"
            value={fmtNum(d.totals.failures)}
            tone={d.totals.failures > 0 ? "high" : "default"}
          />
        </div>

        <div className="text-xs text-fg-subtle">
          {d.by_source
            .map((s) => `${SOURCE_LABEL[s.source] ?? s.source}: ${fmtNum(s.count)}`)
            .join(" · ")}
        </div>

        <div className="cloudtrail-view">
          <Card className="overflow-hidden p-0">
            <CardHeader title="Most-accessed objects" icon={FileSearch} className="px-4 py-3" />
            <DataTable
              columns={objectCols}
              rows={d.top_objects}
              getRowKey={(r) => r.resource_id}
              initialSort={{ key: "count", dir: "desc" }}
              filterPlaceholder="Filter objects…"
              emptyLabel="No objects match."
            />
          </Card>
        </div>

        <div className="cloudtrail-view grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card className="overflow-hidden p-0">
            <CardHeader
              title="Top principals"
              subtitle="Who is touching the data"
              icon={UserRound}
              className="px-4 py-3"
            />
            <DataTable
              columns={principalCols}
              rows={d.top_principals}
              getRowKey={(r) => r.principal}
              initialSort={{ key: "count", dir: "desc" }}
              filterPlaceholder="Filter principals…"
              emptyLabel="No principals match."
            />
          </Card>

          <Card className="overflow-hidden p-0">
            <CardHeader
              title="Source IPs"
              subtitle="Where access originated"
              icon={Globe2}
              className="px-4 py-3"
            />
            <DataTable
              columns={ipCols}
              rows={d.top_ips}
              getRowKey={(r) => r.source_ip}
              initialSort={{ key: "count", dir: "desc" }}
              filterPlaceholder="Filter IPs…"
              emptyLabel="No source IPs match."
            />
          </Card>
        </div>
      </PanelBody>
    </>
  );
}
