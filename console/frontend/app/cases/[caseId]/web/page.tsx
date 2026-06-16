"use client";

import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Entity } from "@/components/pivot";
import { StatCard } from "@/components/stat";
import { Card, CardHeader, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtNum } from "@/lib/format";
import { useQuery } from "@tanstack/react-query";
import { Globe2, Network, Server, ShieldAlert } from "lucide-react";

const SOURCE_LABEL: Record<string, string> = {
  elb_alb: "ELB / ALB",
  cloudfront: "CloudFront",
  waf: "WAF",
  route53_resolver: "Route53 Resolver",
};

function MiniBars({ rows }: { rows: { label: string; count: number; tone?: string }[] }) {
  const max = Math.max(...rows.map((r) => r.count), 1);
  return (
    <div className="space-y-2 p-4">
      {rows.map((r) => (
        <div key={r.label}>
          <div className="flex items-center justify-between gap-2 text-xs">
            <span className="truncate text-fg" title={r.label}>
              {r.label}
            </span>
            <span className="mono text-fg-subtle">{fmtNum(r.count)}</span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div
              className={`h-full rounded-full ${r.tone ?? "bg-accent/60"}`}
              style={{ width: `${(r.count / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
      {rows.length === 0 && (
        <div className="py-4 text-center text-xs text-fg-subtle">No data.</div>
      )}
    </div>
  );
}

export default function WebDnsPage() {
  const { caseId } = useCase();
  const q = useQuery({ queryKey: ["web-dns", caseId], queryFn: () => api.webDns(caseId) });

  if (q.isLoading || !q.data) return <LoadingPanel label="Loading web & DNS…" />;
  const { edge, waf, dns } = q.data;

  const empty =
    edge.totals.requests === 0 && waf.totals.sampled === 0 && dns.totals.queries === 0;

  if (empty) {
    return (
      <>
        <PanelHeader icon={Globe2} title="Web & DNS" panel="web" />
        <PanelBody>
          <Card className="py-4">
            <EmptyState
              icon={Globe2}
              title="No L7 edge, WAF, or DNS records in this case"
              description="ELB/ALB and CloudFront access logging, WAF sampled requests, and Route53 Resolver query logs were not in scope for this window. Any gaps are recorded in the manifest."
            />
          </Card>
        </PanelBody>
      </>
    );
  }

  return (
    <>
      <PanelHeader
        icon={Globe2}
        title="Web & DNS"
        description="L7 edge requests, WAF verdicts, and DNS — what was requested, by whom, with what result. Pivot any IP into the Timeline to correlate across layers."
        panel="web"
      />
      <PanelBody className="space-y-6">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <StatCard label="Edge requests" value={fmtNum(edge.totals.requests)} icon={Network} />
          <StatCard label="Edge clients" value={fmtNum(edge.totals.clients)} icon={Globe2} />
          <StatCard
            label="4xx / 5xx"
            value={fmtNum(edge.totals.failures)}
            tone={edge.totals.failures > 0 ? "high" : "default"}
          />
          <StatCard
            label="WAF blocked"
            value={fmtNum(waf.totals.blocked)}
            sub={`${fmtNum(waf.totals.sampled)} sampled`}
            tone={waf.totals.blocked > 0 ? "high" : "default"}
            icon={ShieldAlert}
          />
          <StatCard
            label="DNS queries"
            value={fmtNum(dns.totals.queries)}
            sub={`${fmtNum(dns.totals.domains)} domains`}
            icon={Server}
          />
        </div>

        {/* -- Edge requests (ELB/ALB + CloudFront) ----------------------------------------- */}
        <div>
          <div className="mb-3 flex items-center gap-2">
            <h2 className="text-sm font-semibold">Edge requests</h2>
            <span className="text-xs text-fg-subtle">
              {edge.by_source
                .map((s) => `${SOURCE_LABEL[s.source] ?? s.source} ${fmtNum(s.count)}`)
                .join(" · ")}
            </span>
          </div>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader
                title="Top clients"
                subtitle="Requesting IPs across ELB/ALB and CloudFront"
                icon={Globe2}
              />
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                    <th className="px-4 py-2">Client IP</th>
                    <th className="px-4 py-2 text-right">Requests</th>
                    <th className="px-4 py-2 text-right">4xx / 5xx</th>
                  </tr>
                </thead>
                <tbody>
                  {edge.top_clients.map((c) => (
                    <tr key={c.source_ip} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2">
                        <Entity kind="ip" value={c.source_ip} />
                      </td>
                      <td className="px-4 py-2 text-right mono text-xs">{fmtNum(c.requests)}</td>
                      <td className="px-4 py-2 text-right mono text-xs">
                        {c.failures > 0 ? (
                          <span className="text-high">{fmtNum(c.failures)}</span>
                        ) : (
                          <span className="text-fg-subtle">0</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {edge.top_clients.length === 0 && (
                    <tr>
                      <td colSpan={3} className="px-4 py-6 text-center text-xs text-fg-subtle">
                        No edge requests.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </Card>

            <div className="grid grid-cols-1 gap-6">
              <Card>
                <CardHeader title="Methods" subtitle="HTTP methods seen at the edge" />
                <MiniBars
                  rows={edge.methods.map((m) => ({ label: m.method, count: m.count }))}
                />
              </Card>
              <Card>
                <CardHeader title="Targets" subtitle="Load balancers and distributions" />
                <MiniBars
                  rows={edge.top_resources.map((r) => ({
                    label: `${SOURCE_LABEL[r.source] ?? r.source}: ${r.resource_id}`,
                    count: r.count,
                  }))}
                />
              </Card>
            </div>
          </div>

          {edge.user_agents.length > 0 && (
            <Card className="mt-6">
              <CardHeader
                title="User agents"
                subtitle="Cluster on unusual or scripted agents"
              />
              <table className="w-full text-sm">
                <tbody>
                  {edge.user_agents.map((u) => (
                    <tr key={u.ua} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2">
                        <span className="mono truncate text-xs text-fg" title={u.ua}>
                          {u.ua}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-right mono text-xs text-fg-subtle">
                        {fmtNum(u.count)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}
        </div>

        {/* -- WAF + DNS -------------------------------------------------------------------- */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader
              title="WAF"
              subtitle={`${fmtNum(waf.totals.sampled)} sampled · ${fmtNum(waf.totals.blocked)} blocked`}
              icon={ShieldAlert}
            />
            {waf.totals.sampled === 0 ? (
              <div className="px-4 py-6 text-xs text-fg-subtle">
                No WAF sampled requests in this case. WAF sampling only covers the previous 3
                hours at collection time; re-run the collector closer to the activity window.
              </div>
            ) : (
              <>
                <div className="border-b border-border/60">
                  <MiniBars
                    rows={waf.actions.map((a) => ({
                      label: a.action.replace("waf:", "").toUpperCase(),
                      count: a.count,
                      tone: /block|captcha|challenge/i.test(a.action)
                        ? "bg-high/70"
                        : "bg-accent/60",
                    }))}
                  />
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
                        <td className="px-4 py-2">
                          <Entity kind="ip" value={c.source_ip} />
                        </td>
                        <td className="px-4 py-2 text-xs text-fg-subtle">{c.country || "—"}</td>
                        <td className="px-4 py-2 text-right mono text-xs">{fmtNum(c.count)}</td>
                        <td className="px-4 py-2 text-right mono text-xs">
                          {c.blocked > 0 ? (
                            <span className="text-high">{fmtNum(c.blocked)}</span>
                          ) : (
                            <span className="text-fg-subtle">0</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </Card>

          <Card>
            <CardHeader
              title="DNS resolver queries"
              subtitle="Failed lookups (NXDOMAIN/SERVFAIL) are the C2 / DGA / exfil lens"
              icon={Server}
            />
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                  <th className="px-4 py-2">Domain</th>
                  <th className="px-4 py-2 text-right">Queries</th>
                  <th className="px-4 py-2 text-right">Failed</th>
                </tr>
              </thead>
              <tbody>
                {dns.top_domains.map((d) => (
                  <tr key={d.domain} className="row-hover border-b border-border/60">
                    <td className="px-4 py-2">
                      <Entity kind="resource" value={d.domain} truncate />
                    </td>
                    <td className="px-4 py-2 text-right mono text-xs">{fmtNum(d.count)}</td>
                    <td className="px-4 py-2 text-right mono text-xs">
                      {d.failures > 0 ? (
                        <span className="text-high">{fmtNum(d.failures)}</span>
                      ) : (
                        <span className="text-fg-subtle">0</span>
                      )}
                    </td>
                  </tr>
                ))}
                {dns.top_domains.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-4 py-6 text-center text-xs text-fg-subtle">
                      No DNS resolver query logs.
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
