"use client";

import { useCase } from "@/components/case-context";
import { DnsQueryTable } from "@/components/dns-query-table";
import { EdgeRequestTable } from "@/components/edge-request-table";
import {
  EdgeRequestToolbar,
  type EdgeRequestFilters,
} from "@/components/edge-request-toolbar";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Entity } from "@/components/pivot";
import { StatCard } from "@/components/stat";
import { TablePager } from "@/components/table-pager";
import { Card, CardHeader, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { caseCloud } from "@/lib/cloud-sources";
import { fmtNum } from "@/lib/format";
import { panelLabel } from "@/lib/panel-labels";
import {
  ALL_EDGE_REQUEST_COL_KEYS,
  EDGE_REQUEST_VISIBLE_COLS_KEY,
  EDGE_SOURCE_CHIP,
  EDGE_SOURCE_LABEL,
  loadVisibleEdgeRequestCols,
  type EdgeRequestColKey,
} from "@/lib/edge-request-columns";
import { usePagination } from "@/lib/pagination";
import { cn } from "@/lib/utils";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Globe2, Network, Route, Search, Server, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

const BASE_EDGE_SOURCES = ["elb_alb", "cloudfront"];

const SOURCE_LABEL: Record<string, string> = EDGE_SOURCE_LABEL;

/** Colored chips for edge-source breakdown in section headers. */
const EDGE_SOURCE_CHIP_STYLE: Record<string, { chip: string; dot: string }> = {
  elb_alb: { chip: EDGE_SOURCE_CHIP.elb_alb, dot: "bg-accent" },
  cloudfront: { chip: EDGE_SOURCE_CHIP.cloudfront, dot: "bg-ok-green" },
};

function EdgeSourceChips({ sources }: { sources: { source: string; count: number }[] }) {
  if (sources.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {sources.map((s) => {
        const style = EDGE_SOURCE_CHIP_STYLE[s.source] ?? {
          chip: "border-border bg-surface-2 text-fg-subtle",
          dot: "bg-fg-subtle",
        };
        return (
          <span
            key={s.source}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium",
              style.chip,
            )}
          >
            <span className={cn("h-2 w-2 shrink-0 rounded-full", style.dot)} aria-hidden />
            <span>{SOURCE_LABEL[s.source] ?? s.source}</span>
            <span className="mono text-sm font-semibold text-fg">{fmtNum(s.count)}</span>
          </span>
        );
      })}
    </div>
  );
}

const STATUS_TONE: Record<string, string> = {
  "2xx": "bg-ok-green/70",
  "3xx": "bg-accent/50",
  "4xx": "bg-warn-amber/80",
  "5xx": "bg-bad-red/80",
  other: "bg-surface-3",
};

function DnsQueryLog({ caseId }: { caseId: string }) {
  const [q, setQ] = useState("");
  const { page, setPage, pageSize, setPageSize } = usePagination("ventra.dns-queries.page-size");

  const eventsQ = useQuery({
    queryKey: ["dns-queries", caseId, q, page, pageSize],
    queryFn: () =>
      api.events(caseId, {
        source: ["route53_resolver"],
        q: q || undefined,
        sort: "timestamp",
        order: "desc",
        limit: pageSize,
        offset: page * pageSize,
      }),
    placeholderData: keepPreviousData,
  });

  const matched = eventsQ.data?.total ?? 0;

  return (
    <>
      <div className="ct-filter-bar border-b border-border/60 px-3 py-2">
        <div className="ct-filter-controls">
          <div className="ct-search-wrap">
            <Search className="ct-search-icon" aria-hidden />
            <input
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(0);
              }}
              placeholder="Search domains, IPs, instance IDs…"
              className="ct-input ct-input-full ct-input-search"
            />
          </div>
          <span className="mono text-xs text-fg-subtle">{fmtNum(matched)} queries</span>
        </div>
      </div>
      <DnsQueryTable events={eventsQ.data?.events ?? []} loading={eventsQ.isPending && !eventsQ.data} />
      <TablePager
        page={page}
        pageSize={pageSize}
        total={matched}
        shown={eventsQ.data?.events.length ?? 0}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
      />
    </>
  );
}

function MiniBars({
  rows,
}: {
  rows: { key: string; label: string; count: number; tone?: string }[];
}) {
  const max = Math.max(...rows.map((r) => r.count), 1);
  return (
    <div className="space-y-2 p-4">
      {rows.map((r) => (
        <div key={r.key}>
          <div className="flex items-center justify-between gap-2 text-xs">
            <span className="truncate text-fg" title={r.label}>{r.label}</span>
            <span className="mono shrink-0 text-fg-subtle">{fmtNum(r.count)}</span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div className={cn("h-full rounded-full", r.tone ?? "bg-accent/60")}
              style={{ width: `${(r.count / max) * 100}%` }} />
          </div>
        </div>
      ))}
      {rows.length === 0 && <div className="py-4 text-center text-xs text-fg-subtle">No data.</div>}
    </div>
  );
}

function StatusBar({ classes }: { classes: { cls: string; count: number }[] }) {
  const total = classes.reduce((a, c) => a + c.count, 0) || 1;
  const order = ["2xx", "3xx", "4xx", "5xx", "other"];
  const sorted = [...classes].sort((a, b) => order.indexOf(a.cls) - order.indexOf(b.cls));
  return (
    <div className="p-4">
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface-2">
        {sorted.map((c) => (
          <div key={c.cls} title={`${c.cls}: ${fmtNum(c.count)}`}
            className={STATUS_TONE[c.cls] ?? "bg-surface-3"}
            style={{ width: `${(c.count / total) * 100}%` }} />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-3 text-2xs text-fg-subtle">
        {sorted.map((c) => (
          <span key={c.cls} className="flex items-center gap-1.5">
            <span className={cn("h-2.5 w-2.5 rounded-sm", STATUS_TONE[c.cls])} />
            <span className={cn("uppercase", (c.cls === "4xx" || c.cls === "5xx") && "text-fg")}>
              {c.cls}
            </span>
            <span className="mono text-fg">{fmtNum(c.count)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function EdgeRequestLog({ caseId }: { caseId: string }) {
  const [filters, setFilters] = useState<EdgeRequestFilters>({});
  const [visibleColumns, setVisibleColumns] = useState<EdgeRequestColKey[]>(
    ALL_EDGE_REQUEST_COL_KEYS,
  );
  const { page, setPage, pageSize, setPageSize } = usePagination("ventra.edge-requests.page-size");

  useEffect(() => {
    setVisibleColumns(loadVisibleEdgeRequestCols());
  }, []);

  const handleColumnsChange = useCallback((cols: EdgeRequestColKey[]) => {
    setVisibleColumns(cols);
    try {
      localStorage.setItem(EDGE_REQUEST_VISIBLE_COLS_KEY, JSON.stringify(cols));
    } catch {
      /* ignore */
    }
  }, []);

  const effectiveSources = filters.sources?.length ? filters.sources : BASE_EDGE_SOURCES;

  const eventParams = useMemo(
    () => ({
      source: effectiveSources,
      q: filters.q,
      actions: filters.methods,
      resources: filters.resources,
      http_status: filters.statuses,
      sort: "timestamp" as const,
      order: "desc" as const,
    }),
    [effectiveSources, filters],
  );

  const eventsQ = useQuery({
    queryKey: ["edge-requests", caseId, eventParams, page, pageSize],
    queryFn: () =>
      api.events(caseId, {
        ...eventParams,
        limit: pageSize,
        offset: page * pageSize,
      }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["edge-facets", caseId],
    queryFn: () => api.facets(caseId, { source: BASE_EDGE_SOURCES }),
  });

  const matched = eventsQ.data?.total ?? 0;

  const handleChange = useCallback((next: Partial<EdgeRequestFilters>) => {
    setFilters((prev) => {
      const merged = { ...prev, ...next };
      for (const key of Object.keys(next) as (keyof EdgeRequestFilters)[]) {
        if (next[key] === undefined) delete merged[key];
      }
      return merged;
    });
    setPage(0);
  }, [setPage]);

  const handleReset = useCallback(() => {
    setFilters({});
    setPage(0);
  }, [setPage]);

  return (
    <div className="cloudtrail-view edge-requests-log mt-8">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-fg">Request log</h2>
          <p className="mt-0.5 text-xs text-fg-subtle">
            Every ELB/ALB and CloudFront access-log line
          </p>
        </div>
        <span className="mono text-xs text-fg-subtle">{fmtNum(matched)} requests</span>
      </div>

      <EdgeRequestToolbar
        facets={facetsQ.data}
        filters={filters}
        visibleColumns={visibleColumns}
        onChange={handleChange}
        onColumnsChange={handleColumnsChange}
        onReset={handleReset}
      />

      <div className="ct-panel">
        <EdgeRequestTable
          events={eventsQ.data?.events ?? []}
          loading={eventsQ.isPending && !eventsQ.data}
          visibleColumns={visibleColumns}
        />
        <TablePager
          page={page}
          pageSize={pageSize}
          total={matched}
          shown={eventsQ.data?.events.length ?? 0}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      </div>
    </div>
  );
}

export default function WebDnsPage() {
  const { caseId, summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const title = panelLabel(cloud, "web");
  const q = useQuery({ queryKey: ["web-dns", caseId], queryFn: () => api.webDns(caseId) });

  if (q.isLoading || !q.data) return <LoadingPanel label="Loading web & DNS…" />;
  const { edge, waf, dns } = q.data;
  const showPathCounts = edge.top_paths.some((p) => p.count != null);
  const showPathFailures = edge.top_paths.some((p) => p.failures != null && p.failures > 0);
  const pathColSpan = 1 + (showPathCounts ? 1 : 0) + (showPathFailures ? 1 : 0);

  const empty =
    edge.totals.requests === 0 && waf.totals.sampled === 0 && dns.totals.queries === 0;

  if (empty) {
    return (
      <>
        <PanelHeader icon={Globe2} title={title} panel="web" />
        <PanelBody>
          <Card className="py-4">
            <EmptyState
              icon={Globe2}
              title="No L7 edge, WAF, or DNS records in this case"
              description={
                cloud === "azure"
                  ? "Application Gateway, Front Door, and DNS query logs were not in scope for this window. Any gaps are recorded in the manifest."
                  : cloud === "gcp"
                    ? "Cloud Load Balancer and API Gateway access logs were not in scope for this window. Any gaps are recorded in the manifest."
                    : "ELB/ALB and CloudFront access logging, WAF sampled requests, and Route53 Resolver query logs were not in scope for this window. Any gaps are recorded in the manifest."
              }
            />
          </Card>
        </PanelBody>
      </>
    );
  }

  return (
    <>
      <PanelHeader icon={Globe2} title={title} panel="web" />
      <PanelBody className="space-y-6">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <StatCard label="Edge requests" value={fmtNum(edge.totals.requests)} icon={Network} />
          <StatCard label="Edge clients" value={fmtNum(edge.totals.clients)} icon={Globe2} />
          <StatCard label="4xx / 5xx" value={fmtNum(edge.totals.failures)}
            tone={edge.totals.failures > 0 ? "high" : "default"} />
          <StatCard label="WAF blocked" value={fmtNum(waf.totals.blocked)}
            sub={`${fmtNum(waf.totals.sampled)} sampled`}
            tone={waf.totals.blocked > 0 ? "high" : "default"} icon={ShieldAlert} />
          <StatCard label="DNS queries" value={fmtNum(dns.totals.queries)}
            sub={`${fmtNum(dns.totals.failures)} failed`}
            tone={dns.totals.failures > 0 ? "high" : "default"} icon={Server} />
        </div>

        {/* -- Edge requests (ELB/ALB + CloudFront) ----------------------------------------- */}
        <div>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-fg">Edge requests</h2>
            <EdgeSourceChips sources={edge.by_source} />
          </div>

          {edge.status_classes.length > 0 && (
            <Card className="mb-6">
              <CardHeader title="Response status" />
              <StatusBar classes={edge.status_classes} />
            </Card>
          )}

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card className="overflow-hidden">
              <CardHeader title="Top requested paths" subtitle="Admin/login probing surfaces here" icon={Route} />
              <div className="overflow-x-auto">
                <table className="min-w-full w-max text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                      <th className="px-4 py-2 whitespace-nowrap">Target</th>
                      {showPathCounts && (
                        <th className="px-4 py-2 text-right whitespace-nowrap w-24">Requests</th>
                      )}
                      {showPathFailures && (
                        <th className="px-4 py-2 text-right whitespace-nowrap w-24">4xx/5xx</th>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {edge.top_paths.map((p) => (
                      <tr key={p.target} className="row-hover border-b border-border/60">
                        <td className="px-4 py-2">
                          <span className="mono block whitespace-nowrap text-xs text-fg">{p.target}</span>
                        </td>
                        {showPathCounts && (
                          <td className="px-4 py-2 text-right mono text-xs whitespace-nowrap">
                            {p.count != null ? fmtNum(p.count) : "—"}
                          </td>
                        )}
                        {showPathFailures && (
                          <td className="px-4 py-2 text-right mono text-xs whitespace-nowrap">
                            {p.failures != null && p.failures > 0 ? (
                              <span className="text-high">{fmtNum(p.failures)}</span>
                            ) : (
                              <span className="text-fg-subtle">0</span>
                            )}
                          </td>
                        )}
                      </tr>
                    ))}
                    {edge.top_paths.length === 0 && (
                      <tr><td colSpan={pathColSpan} className="px-4 py-6 text-center text-xs text-fg-subtle">No edge requests.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            <Card>
              <CardHeader title="Top clients" subtitle="Requesting IPs across ELB/ALB and CloudFront" icon={Globe2} />
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                    <th className="px-4 py-2">Client IP</th>
                    <th className="px-4 py-2 text-right">Requests</th>
                    <th className="px-4 py-2 text-right">4xx/5xx</th>
                  </tr>
                </thead>
                <tbody>
                  {edge.top_clients.map((c) => (
                    <tr key={c.source_ip} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2"><Entity kind="ip" value={c.source_ip} /></td>
                      <td className="px-4 py-2 text-right mono text-xs">{fmtNum(c.requests)}</td>
                      <td className="px-4 py-2 text-right mono text-xs">
                        {c.failures > 0 ? <span className="text-high">{fmtNum(c.failures)}</span>
                          : <span className="text-fg-subtle">0</span>}
                      </td>
                    </tr>
                  ))}
                  {edge.top_clients.length === 0 && (
                    <tr><td colSpan={3} className="px-4 py-6 text-center text-xs text-fg-subtle">No edge requests.</td></tr>
                  )}
                </tbody>
              </table>
            </Card>
          </div>

          <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card className="overflow-hidden">
              <CardHeader title="Methods" subtitle="HTTP methods seen at the edge" />
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                    <th className="px-4 py-2">Method</th>
                    <th className="px-4 py-2 text-right">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {edge.methods.map((m) => (
                    <tr key={m.method} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2 mono text-xs font-medium text-fg">
                        {m.method && m.method !== "-" ? m.method : "—"}
                      </td>
                      <td className="px-4 py-2 text-right mono text-xs">{fmtNum(m.count)}</td>
                    </tr>
                  ))}
                  {edge.methods.length === 0 && (
                    <tr><td colSpan={2} className="px-4 py-6 text-center text-xs text-fg-subtle">No data.</td></tr>
                  )}
                </tbody>
              </table>
            </Card>
            <Card className="overflow-hidden">
              <CardHeader title="Targets" subtitle="Load balancers and distributions" />
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                    <th className="px-4 py-2">Target</th>
                    <th className="px-4 py-2">Type</th>
                    <th className="px-4 py-2 text-right">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {edge.top_resources.map((r) => (
                    <tr key={`${r.source}-${r.resource_id}`} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2 mono truncate text-xs text-fg" title={r.resource_id}>
                        {r.resource_id}
                      </td>
                      <td className="px-4 py-2">
                        <span
                          className={cn(
                            "inline-flex rounded-md border px-1.5 py-0.5 text-2xs font-semibold uppercase",
                            EDGE_SOURCE_CHIP[r.source] ?? "border-border bg-surface-2 text-fg-subtle",
                          )}
                        >
                          {SOURCE_LABEL[r.source] ?? r.source}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-right mono text-xs">{fmtNum(r.count)}</td>
                    </tr>
                  ))}
                  {edge.top_resources.length === 0 && (
                    <tr><td colSpan={3} className="px-4 py-6 text-center text-xs text-fg-subtle">No data.</td></tr>
                  )}
                </tbody>
              </table>
            </Card>
          </div>

          {edge.user_agents.length > 0 && (
            <Card className="mt-6">
              <CardHeader title="User agents" subtitle="Cluster on unusual or scripted agents" />
              <table className="w-full text-sm">
                <tbody>
                  {edge.user_agents.map((u) => (
                    <tr key={u.ua} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2">
                        <span className="mono block truncate text-xs text-fg" title={u.ua}>{u.ua}</span>
                      </td>
                      <td className="px-4 py-2 text-right mono text-xs text-fg-subtle">{fmtNum(u.count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}

          <EdgeRequestLog caseId={caseId} />
        </div>

        {/* -- DNS + WAF -------------------------------------------------------------------- */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card className="overflow-hidden p-0">
            <CardHeader title="DNS resolver queries" icon={Server} className="px-4 py-3" />
            <div className="cloudtrail-view dns-queries-log">
              <DnsQueryLog caseId={caseId} />
            </div>
          </Card>

          <Card>
            <CardHeader title="WAF" icon={ShieldAlert} />
            {waf.totals.sampled === 0 ? (
              <div className="px-4 py-6 text-xs text-fg-subtle">
                No WAF sampled requests in this case. WAF sampling only covers the previous 3
                hours at collection time; re-run the collector closer to the activity window.
              </div>
            ) : (
              <>
                <div className="border-b border-border/60">
                  <MiniBars rows={waf.actions.map((a) => ({
                    key: a.action,
                    label: a.action.replace("waf:", "").toUpperCase(),
                    count: a.count,
                    tone: /block|captcha|challenge/i.test(a.action) ? "bg-high/70" : "bg-accent/60",
                  }))} />
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                      <th className="px-4 py-2">Client IP</th>
                      <th className="px-4 py-2">Country</th>
                      <th className="px-4 py-2 text-right">Requests</th>
                      <th className="px-4 py-2 text-right">Blocked</th>
                    </tr>
                  </thead>
                  <tbody>
                    {waf.top_ips.map((c) => (
                      <tr key={c.source_ip} className="row-hover border-b border-border/60">
                        <td className="px-4 py-2"><Entity kind="ip" value={c.source_ip} /></td>
                        <td className="px-4 py-2 text-xs text-fg-subtle">{c.country || "—"}</td>
                        <td className="px-4 py-2 text-right mono text-xs">{fmtNum(c.count)}</td>
                        <td className="px-4 py-2 text-right mono text-xs">
                          {c.blocked > 0 ? <span className="text-high">{fmtNum(c.blocked)}</span>
                            : <span className="text-fg-subtle">0</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </Card>
        </div>
      </PanelBody>
    </>
  );
}
