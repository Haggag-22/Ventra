"use client";

import { useCase } from "@/components/case-context";
import { HBars } from "@/components/charts";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Entity } from "@/components/pivot";
import { StatCard } from "@/components/stat";
import { Card, CardHeader, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtBytes, fmtNum } from "@/lib/format";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpFromLine, Ban, Network, Upload } from "lucide-react";

function isPublic(ip: string): boolean {
  if (!ip) return false;
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) return false;
  const m = ip.match(/^172\.(\d+)\./);
  if (m && +m[1] >= 16 && +m[1] <= 31) return false;
  return /^\d+\.\d+\.\d+\.\d+$/.test(ip);
}

export default function NetworkPage() {
  const { caseId } = useCase();
  const q = useQuery({ queryKey: ["network", caseId], queryFn: () => api.network(caseId) });

  if (q.isLoading || !q.data) return <LoadingPanel label="Loading network…" />;
  const n = q.data;

  if (n.totals.flows === 0) {
    return (
      <>
        <PanelHeader
          icon={Network}
          title="Network Activity"
          panel="network"
        />
        <PanelBody>
          <Card className="py-4">
            <EmptyState
              icon={Network}
              title="No VPC Flow Logs in this case"
              description="Flow logging was not configured, or its records are delivered to S3 and weren't in scope. Egress volume cannot be quantified for this window — this gap is recorded in the manifest."
            />
          </Card>
        </PanelBody>
      </>
    );
  }

  const publicEgress = n.top_talkers.filter((t) => isPublic(t.dest_ip));

  return (
    <>
      <PanelHeader
        icon={Network}
        title="Network Activity"
        panel="network"
      />
      <PanelBody className="space-y-6">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatCard label="Flows" value={fmtNum(n.totals.flows)} icon={Network} />
          <StatCard label="Total bytes" value={fmtBytes(n.totals.bytes)} icon={Upload} />
          <StatCard label="Public egress" value={fmtBytes(publicEgress.reduce((a, t) => a + t.bytes, 0))}
            icon={ArrowUpFromLine} tone="high" sub={`${publicEgress.length} destinations`} />
          <StatCard label="Rejected flows" value={fmtNum(n.totals.rejects)} icon={Ban} />
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Top talkers — the exfil lens */}
          <Card>
            <CardHeader
              title="Top destinations by volume"
              subtitle="Public destinations are the exfiltration lens"
              icon={ArrowUpFromLine}
            />
            <div className="space-y-2 p-4">
              {n.top_talkers.map((t) => {
                const pub = isPublic(t.dest_ip);
                const max = Math.max(...n.top_talkers.map((x) => x.bytes), 1);
                return (
                  <div key={t.dest_ip} className="group">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="flex items-center gap-2">
                        <Entity kind="ip" value={t.dest_ip} />
                        {pub ? (
                          <span className="chip border-high/30 bg-high/10 text-high">public</span>
                        ) : (
                          <span className="chip">internal</span>
                        )}
                      </span>
                      <span className="mono text-fg">{fmtBytes(t.bytes)}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-2">
                      <div
                        className={`h-full rounded-full ${pub ? "bg-high/70" : "bg-accent/60"}`}
                        style={{ width: `${(t.bytes / max) * 100}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>

          {/* Rejected flows */}
          <Card>
            <CardHeader title="Rejected flows" subtitle="Blocked connection attempts" icon={Ban} />
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                  <th className="px-4 py-2">Source</th>
                  <th className="px-4 py-2">Dest</th>
                  <th className="px-4 py-2">Port</th>
                  <th className="px-4 py-2 text-right">Count</th>
                </tr>
              </thead>
              <tbody>
                {n.rejected.map((r, i) => (
                  <tr key={i} className="row-hover border-b border-border/60">
                    <td className="px-4 py-2">
                      <Entity kind="ip" value={r.source_ip} />
                    </td>
                    <td className="px-4 py-2">
                      <Entity kind="ip" value={r.dest_ip} />
                    </td>
                    <td className="px-4 py-2 mono text-xs text-fg-subtle">{r.dest_port}</td>
                    <td className="px-4 py-2 text-right mono text-xs">{fmtNum(r.count)}</td>
                  </tr>
                ))}
                {n.rejected.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-xs text-fg-subtle">
                      No rejected flows.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Card>
        </div>
      </PanelBody>
    </>
  );
}
