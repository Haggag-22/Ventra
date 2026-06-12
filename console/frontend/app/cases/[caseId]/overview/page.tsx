"use client";

import { useCase } from "@/components/case-context";
import { Donut, HBars } from "@/components/charts";
import { PanelBody, PanelHeader } from "@/components/panel";
import { StatCard } from "@/components/stat";
import { Card, CardHeader, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtNum, relativeSpan, titleCase } from "@/lib/format";
import { baselineCollectorIds, gapsForCollector } from "@/lib/collection-coverage";
import { catalogItem } from "@/lib/panel-collectors";
import type { Cloud } from "@/lib/catalog";
import { CATEGORY_COLORS, severityHex } from "@/lib/severity";
import type { Severity } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Gauge,
  Globe,
  KeyRound,
  ShieldAlert,
  ShieldX,
  Users,
  XCircle,
} from "lucide-react";
import { useRouter } from "next/navigation";

const REASON_LABEL: Record<string, string> = {
  service_not_enabled: "Service not enabled",
  logging_not_configured: "Logging not configured",
  access_denied: "Access denied",
  region_opted_out: "Region opted out",
  not_present: "Not present",
  collector_error: "Collector error",
  log_integrity_failed: "Log integrity failed",
  out_of_scope: "Out of scope",
};

export default function OverviewPage() {
  const { caseId } = useCase();
  const router = useRouter();
  const summary = useQuery({ queryKey: ["summary", caseId], queryFn: () => api.summary(caseId) });

  if (summary.isLoading || !summary.data) return <LoadingPanel label="Loading overview…" />;
  const s = summary.data;

  const sevData = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((k) => ({ label: k, value: s.by_severity[k] ?? 0, color: severityHex(k) }))
    .filter((d) => d.value > 0);

  const catData = Object.entries(s.by_category)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ label: k, value: v, color: CATEGORY_COLORS[k] ?? "rgb(120 120 120)" }));

  const goEvents = (params: Record<string, string>) => {
    const sp = new URLSearchParams(params).toString();
    router.push(`/cases/${caseId}/timeline?${sp}`);
  };

  const baseline = baselineCollectorIds(s.cloud as Cloud);
  const collected = new Set(s.collection?.collected ?? []);
  const allGaps = s.collection?.gaps ?? [];

  return (
    <>
      <PanelHeader icon={Gauge} title="Overview" />
      <PanelBody className="space-y-6">
        {/* Stat row */}
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <StatCard label="Events" value={fmtNum(s.totals.events)} icon={ShieldAlert}
            sub={relativeSpan(s.event_span.first, s.event_span.last) + " span"} />
          <StatCard label="Principals" value={fmtNum(s.totals.principals)} icon={Users}
            onClick={() => router.push(`/cases/${caseId}/identity`)} />
          <StatCard label="Source IPs" value={fmtNum(s.totals.source_ips)} icon={Globe}
            onClick={() => router.push(`/cases/${caseId}/network`)} />
          <StatCard label="High+ severity" value={fmtNum(s.totals.sensitive_actions)} icon={KeyRound}
            tone="high" onClick={() => goEvents({ severity: "critical" })} />
          <StatCard label="Denied / failed" value={fmtNum(s.totals.failures)} icon={XCircle}
            onClick={() => goEvents({ outcome: "failure" })} />
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Collection completeness — read this first */}
          <Card className="lg:col-span-1">
            <CardHeader
              title="Logs completeness"
              subtitle="A disabled or empty source changes how you read everything else"
              icon={CheckCircle2}
            />
            <div className="divide-y divide-border">
              {baseline.map((name) => {
                const hasData = collected.has(name);
                const childGaps = gapsForCollector(name, allGaps);
                const gap = childGaps[0] ?? allGaps.find((g) => g.name === name);
                const label = catalogItem(s.cloud as Cloud, name)?.label ?? name;
                return (
                  <div key={name} className="flex items-center justify-between px-4 py-2">
                    <span className="text-xs text-fg">{label}</span>
                    {hasData && !childGaps.length ? (
                      <span className="flex items-center gap-1 text-2xs text-ok-green">
                        <CheckCircle2 className="h-3.5 w-3.5" /> collected
                      </span>
                    ) : hasData && childGaps.length ? (
                      <span
                        className="flex items-center gap-1 text-2xs text-warn-amber"
                        title={childGaps.map((g) => g.detail).join(" ")}
                      >
                        <AlertTriangle className="h-3.5 w-3.5" />
                        partial
                      </span>
                    ) : (
                      <span
                        className="flex items-center gap-1 text-2xs text-warn-amber"
                        title={gap?.detail}
                      >
                        <ShieldX className="h-3.5 w-3.5" />
                        {gap ? REASON_LABEL[gap.reason] ?? gap.reason : "missing"}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
            {(allGaps.length > 0) && (
              <div className="border-t border-border px-4 py-3">
                <div className="flex items-start gap-2 text-2xs text-fg-subtle">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warn-amber" />
                  {allGaps.some((g) => g.name === "vpc_flow" || g.name.startsWith("vpc"))
                    ? "VPC Flow Logs not enabled — exfiltration volume cannot be quantified for this window."
                    : "Some sources were unavailable; gaps are recorded as evidence in the manifest."}
                </div>
              </div>
            )}
          </Card>

          {/* Severity + category */}
          <Card className="lg:col-span-2">
            <CardHeader title="Event distribution" subtitle="By severity and category" />
            <div className="grid grid-cols-1 gap-6 p-4 sm:grid-cols-2">
              <Donut
                data={sevData}
                centerValue={fmtNum(s.totals.events)}
                centerLabel="events"
              />
              <div>
                <div className="stat-label mb-2">By category</div>
                <HBars
                  data={catData.map((c) => ({ label: titleCase(c.label), value: c.value }))}
                  onClick={(label) =>
                    goEvents({ category: label.toLowerCase() })
                  }
                />
              </div>
            </div>
          </Card>
        </div>

        {/* Top principals + IPs */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader title="Top principals" icon={Users} />
            <div className="p-4">
              <HBars
                data={s.top_principals.map(([k, v]) => ({ label: k, value: v }))}
                onClick={(label) => goEvents({ related_user: label })}
              />
            </div>
          </Card>
          <Card>
            <CardHeader title="Top source IPs" icon={Globe} />
            <div className="p-4">
              <HBars
                data={s.top_source_ips.map(([k, v]) => ({ label: k, value: v }))}
                onClick={(label) => goEvents({ related_ip: label })}
              />
            </div>
          </Card>
        </div>
      </PanelBody>
    </>
  );
}
