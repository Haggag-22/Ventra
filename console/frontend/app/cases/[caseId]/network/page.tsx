"use client";

import { useCase } from "@/components/case-context";
import { SelectDropdown } from "@/components/multiselect";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Entity } from "@/components/pivot";
import { StatCard } from "@/components/stat";
import { TablePager } from "@/components/table-pager";
import { Card, CardHeader, EmptyState, LoadingPanel } from "@/components/ui";
import { VpcFlowTable } from "@/components/vpc-flow-table";
import { VpcFlowToolbar, type VpcFlowFilters } from "@/components/vpc-flow-toolbar";
import { api } from "@/lib/api";
import { fmtBytes, fmtNum } from "@/lib/format";
import { usePagination } from "@/lib/pagination";
import { caseCloud, flowSources } from "@/lib/cloud-sources";
import { panelLabel } from "@/lib/panel-labels";
import {
  ALL_VPC_FLOW_COL_KEYS,
  VPC_FLOW_VISIBLE_COLS_KEY,
  loadVisibleVpcFlowCols,
  type VpcFlowColKey,
} from "@/lib/vpc-flow-columns";
import { cn } from "@/lib/utils";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowUpFromLine, Ban, Network, Plug, Radio, Upload, Users } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

// IANA / IR-relevant port → service. Risky = remote-access, admin, datastore, or known C2.
const PORT_SERVICE: Record<number, string> = {
  20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
  110: "POP3", 123: "NTP", 135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
  161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
  587: "SMTP", 636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
  1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
  4444: "Metasploit", 5432: "Postgres", 5439: "Redshift", 5500: "VNC", 5601: "Kibana",
  5900: "VNC", 5985: "WinRM", 5986: "WinRM/S", 6379: "Redis", 8080: "HTTP-alt",
  8443: "HTTPS-alt", 9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached",
  27017: "MongoDB", 31337: "Backdoor", 1337: "Backdoor",
};
const RISKY_PORTS = new Set([
  21, 22, 23, 135, 137, 139, 445, 1433, 1521, 2049, 3306, 3389, 4444, 5432, 5439, 5500,
  5900, 5985, 5986, 6379, 9200, 9300, 11211, 27017, 1337, 31337,
]);
function svc(port: number): string {
  return PORT_SERVICE[port] ?? "—";
}

function Bar({ value, max, tone = "bg-accent/60" }: { value: number; max: number; tone?: string }) {
  return (
    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-2">
      <div className={cn("h-full rounded-full", tone)} style={{ width: `${(value / Math.max(max, 1)) * 100}%` }} />
    </div>
  );
}

function VpcFlowLog({
  caseId,
  sources,
  vpcId,
}: {
  caseId: string;
  sources: string[];
  vpcId?: string;
}) {
  const [filters, setFilters] = useState<VpcFlowFilters>({ order: "desc" });
  const [visibleColumns, setVisibleColumns] = useState<VpcFlowColKey[]>(ALL_VPC_FLOW_COL_KEYS);
  const { page, setPage, pageSize, setPageSize } = usePagination("ventra.vpc-flow.page-size");

  useEffect(() => {
    setVisibleColumns(loadVisibleVpcFlowCols());
  }, []);

  const handleColumnsChange = useCallback((cols: VpcFlowColKey[]) => {
    setVisibleColumns(cols);
    try {
      localStorage.setItem(VPC_FLOW_VISIBLE_COLS_KEY, JSON.stringify(cols));
    } catch {
      /* ignore */
    }
  }, []);

  const eventParams = useMemo(
    () => ({
      source: sources,
      q: filters.q,
      actions: filters.actions,
      outcomes: filters.outcomes,
      regions: filters.regions,
      source_ips: filters.sourceIps,
      dest_ips: filters.destIps,
      dest_ports: filters.destPorts,
      vpcs: vpcId ? [vpcId] : undefined,
      sort: "timestamp" as const,
      order: filters.order ?? "desc",
    }),
    [filters, sources, vpcId],
  );

  const eventsQ = useQuery({
    queryKey: ["vpc-flow", caseId, eventParams, page, pageSize],
    queryFn: () =>
      api.events(caseId, {
        ...eventParams,
        limit: pageSize,
        offset: page * pageSize,
      }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["vpc-flow-facets", caseId, sources, vpcId],
    queryFn: () =>
      api.facets(caseId, {
        source: sources,
        vpcs: vpcId ? [vpcId] : undefined,
      }),
  });

  const matched = eventsQ.data?.total ?? 0;

  const handleChange = useCallback(
    (next: Partial<VpcFlowFilters>) => {
      setFilters((prev) => {
        const merged = { ...prev, ...next };
        for (const key of Object.keys(next) as (keyof VpcFlowFilters)[]) {
          if (next[key] === undefined) delete merged[key];
        }
        return merged;
      });
      setPage(0);
    },
    [setPage],
  );

  const handleReset = useCallback(() => {
    setFilters({ order: "desc" });
    setPage(0);
  }, [setPage]);

  return (
    <div className="cloudtrail-view vpc-flow-log mt-8">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-fg">Flow log</h2>
          <p className="mt-0.5 text-xs text-fg-subtle">Every flow log record in this case</p>
        </div>
        <span className="mono text-xs text-fg-subtle">{fmtNum(matched)} flows</span>
      </div>

      <VpcFlowToolbar
        facets={facetsQ.data}
        filters={filters}
        visibleColumns={visibleColumns}
        onChange={handleChange}
        onColumnsChange={handleColumnsChange}
        onReset={handleReset}
      />

      <div className="ct-panel">
        <VpcFlowTable
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

function vpcLabel(v: { id: string; name: string }): string {
  return v.name && v.name !== v.id ? `${v.id} (${v.name})` : v.id;
}

export default function NetworkPage() {
  const { caseId, summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const flowSource = flowSources(cloud);
  const [selectedVpc, setSelectedVpc] = useState<string>("");

  const vpcsQ = useQuery({
    queryKey: ["network-vpcs", caseId],
    queryFn: () => api.networkVpcs(caseId),
  });

  useEffect(() => {
    const vpcs = vpcsQ.data?.vpcs ?? [];
    if (vpcs.length === 1 && vpcs[0].flows > 0) {
      setSelectedVpc(vpcs[0].id);
    }
  }, [vpcsQ.data]);

  const vpcFilter = selectedVpc || undefined;
  const q = useQuery({
    queryKey: ["network", caseId, vpcFilter],
    queryFn: () => api.network(caseId, { vpc: vpcFilter }),
    enabled: vpcsQ.isSuccess,
  });

  const vpcs = vpcsQ.data?.vpcs ?? [];
  const vpcOptions = useMemo(
    () => [
      { value: "", label: "All VPCs" },
      ...vpcs.map((v) => ({ value: v.id, label: vpcLabel(v) })),
    ],
    [vpcs],
  );
  const selectedVpcEntry = vpcs.find((v) => v.id === selectedVpc);
  const showVpcDropdown = vpcs.length > 0;
  const vpcDropdown = showVpcDropdown ? (
    <SelectDropdown
      value={selectedVpc}
      options={vpcOptions}
      onChange={setSelectedVpc}
      displayLabel={selectedVpcEntry ? vpcLabel(selectedVpcEntry) : "All VPCs"}
      className="min-w-[280px] justify-between"
      menuClassName="w-80"
    />
  ) : undefined;

  if (vpcsQ.isLoading) {
    return <LoadingPanel label="Loading network…" />;
  }

  const networkLoading = q.isLoading && !q.data;
  const n = q.data;
  const caseFlows = n?.case_totals?.flows ?? 0;
  const filteredFlows = n?.totals?.flows ?? 0;
  const vpcFilterActive = !!vpcFilter;
  const globalEmpty = q.isSuccess && caseFlows === 0;
  const vpcFilteredEmpty =
    q.isSuccess && vpcFilterActive && filteredFlows === 0 && caseFlows > 0;

  if (globalEmpty) {
    return (
      <>
        <PanelHeader icon={Network} title={panelLabel(cloud, "network")} panel="network" actions={vpcDropdown} />
        <PanelBody>
          <Card className="py-4">
            <EmptyState
              icon={Network}
              title="No flow logs in this case"
              description={
                cloud === "azure"
                  ? "NSG or VNet flow logging was not configured, or its records are in storage and weren't in scope. Egress volume cannot be quantified for this window — this gap is recorded in the manifest."
                  : cloud === "gcp"
                    ? "VPC Flow Logs or firewall rule logging was not configured, or records weren't in scope. Egress volume cannot be quantified for this window — this gap is recorded in the manifest."
                    : "VPC flow logging was not configured, or its records are delivered to S3 and weren't in scope. Egress volume cannot be quantified for this window — this gap is recorded in the manifest."
              }
            />
          </Card>
        </PanelBody>
      </>
    );
  }

  if (networkLoading || !n) {
    return (
      <>
        <PanelHeader
          icon={Network}
          title={panelLabel(cloud, "network")}
          panel="network"
          description={
            selectedVpcEntry
              ? `Showing flow logs for ${vpcLabel(selectedVpcEntry)}`
              : vpcs.length > 1
                ? `${vpcs.length} VPCs with flow logging`
                : undefined
          }
          actions={vpcDropdown}
        />
        <PanelBody>
          <LoadingPanel label="Loading network…" />
        </PanelBody>
      </>
    );
  }

  const egressMax = Math.max(...n.egress_public.map((e) => e.bytes), 1);

  return (
    <>
      <PanelHeader
        icon={Network}
        title={panelLabel(cloud, "network")}
        panel="network"
        description={
          selectedVpcEntry
            ? `Showing flow logs for ${vpcLabel(selectedVpcEntry)}`
            : vpcs.length > 1
              ? `${vpcs.length} VPCs with flow logging`
              : undefined
        }
        actions={vpcDropdown}
      />
      <PanelBody className="space-y-6">
        {vpcFilteredEmpty ? (
          <Card className="py-4">
            <EmptyState
              icon={Network}
              title="No flows for this VPC"
              description="No flow records tagged for this VPC in the selected window. Choose All VPCs to see all flow logs."
            />
          </Card>
        ) : (
          <>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <StatCard label="Flows" value={fmtNum(n.totals.flows)} icon={Network}
            sub={`${fmtNum(n.totals.sources)} sources`} />
          <StatCard label="Accepted" value={fmtNum(n.totals.accepted)} icon={Upload} />
          <StatCard label="Rejected" value={fmtNum(n.totals.rejects)} icon={Ban}
            tone={n.totals.rejects > 0 ? "high" : "default"} />
          <StatCard label="Public egress" value={fmtBytes(n.totals.public_bytes)}
            icon={ArrowUpFromLine} tone={n.totals.public_bytes > 0 ? "high" : "default"}
            sub={`of ${fmtBytes(n.totals.bytes)} total`} />
          <StatCard label="External dests" value={fmtNum(n.totals.external_dests)} icon={Radio} />
        </div>

        {/* Hero: exfiltration lens — egress to public IPs by volume */}
        <Card className="overflow-hidden p-0">
          <CardHeader
            title="Egress to public IPs"
            subtitle="Outbound volume to routable addresses"
            icon={ArrowUpFromLine}
          />
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                <th className="px-4 py-2">Destination IP</th>
                <th className="px-4 py-2">Bytes out</th>
                <th className="px-4 py-2 text-right">Flows</th>
                <th className="px-4 py-2 text-right">Ports</th>
              </tr>
            </thead>
            <tbody>
              {n.egress_public.map((e) => (
                <tr key={e.dest_ip} className="row-hover border-b border-border/60">
                  <td className="px-4 py-2">
                    <Entity kind="ip" value={e.dest_ip} />
                  </td>
                  <td className="px-4 py-2">
                    <span className="mono text-xs text-fg">{fmtBytes(e.bytes)}</span>
                    <Bar value={e.bytes} max={egressMax} tone="bg-high/70" />
                  </td>
                  <td className="px-4 py-2 text-right mono text-xs">{fmtNum(e.flows)}</td>
                  <td className="px-4 py-2 text-right mono text-xs text-fg-subtle">{fmtNum(e.ports)}</td>
                </tr>
              ))}
              {n.egress_public.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-xs text-fg-subtle">
                    No egress to public IPs in this window.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card className="overflow-hidden">
            <CardHeader title="Destination ports" subtitle="Flow volume by destination port" icon={Plug} />
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                  <th className="px-4 py-2">Port</th>
                  <th className="px-4 py-2">Service</th>
                  <th className="px-4 py-2 text-right">Flows</th>
                  <th className="px-4 py-2 text-right">Rejected</th>
                  <th className="px-4 py-2 text-right">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {n.top_ports.map((p) => {
                  const risky = RISKY_PORTS.has(p.port);
                  return (
                    <tr key={p.port} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2 mono text-xs text-fg">{p.port}</td>
                      <td className={cn("px-4 py-2 text-xs", risky ? "text-high" : "text-fg-subtle")}>
                        {svc(p.port)}
                      </td>
                      <td className="px-4 py-2 text-right mono text-xs">{fmtNum(p.flows)}</td>
                      <td className="px-4 py-2 text-right mono text-xs">
                        {p.rejected > 0 ? (
                          <span className="text-bad-red">{fmtNum(p.rejected)}</span>
                        ) : (
                          <span className="text-fg-subtle">0</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-right mono text-xs text-fg-subtle">
                        {p.bytes > 0 ? fmtBytes(p.bytes) : "—"}
                      </td>
                    </tr>
                  );
                })}
                {n.top_ports.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-xs text-fg-subtle">
                      No port data.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Card>

          <Card className="overflow-hidden">
            <CardHeader title="Top source talkers" subtitle="Internal hosts by outbound volume" icon={Users} />
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                  <th className="px-4 py-2">Source IP</th>
                  <th className="px-4 py-2 text-right">Bytes</th>
                  <th className="px-4 py-2 text-right">Flows</th>
                </tr>
              </thead>
              <tbody>
                {n.top_talkers.map((t) => (
                  <tr key={t.source_ip} className="row-hover border-b border-border/60">
                    <td className="px-4 py-2">
                      <Entity kind="ip" value={t.source_ip} />
                    </td>
                    <td className="px-4 py-2 text-right mono text-xs text-fg">{fmtBytes(t.bytes)}</td>
                    <td className="px-4 py-2 text-right mono text-xs text-fg-subtle">{fmtNum(t.flows)}</td>
                  </tr>
                ))}
                {n.top_talkers.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-4 py-6 text-center text-xs text-fg-subtle">
                      No source data.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Card>
        </div>

        <Card>
          <CardHeader title="Rejected flows" subtitle="Blocked connection attempts" icon={Ban} />
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                <th className="px-4 py-2">Source</th>
                <th className="px-4 py-2">Dest</th>
                <th className="px-4 py-2">Port</th>
                <th className="px-4 py-2">Service</th>
                <th className="px-4 py-2 text-right">Count</th>
              </tr>
            </thead>
            <tbody>
              {n.rejected.map((r, i) => {
                const risky = r.dest_port > 0 && RISKY_PORTS.has(r.dest_port);
                const service = r.dest_port > 0 ? svc(r.dest_port) : "—";
                return (
                <tr key={i} className="row-hover border-b border-border/60">
                  <td className="px-4 py-2"><Entity kind="ip" value={r.source_ip} /></td>
                  <td className="px-4 py-2"><Entity kind="ip" value={r.dest_ip} /></td>
                  <td className="px-4 py-2 mono text-xs text-fg-subtle">
                    {r.dest_port > 0 ? r.dest_port : <span title="No L4 port (e.g. ICMP)">—</span>}
                  </td>
                  <td className={cn("px-4 py-2 text-xs", risky ? "text-high" : "text-fg-subtle")}>
                    {service}
                  </td>
                  <td className="px-4 py-2 text-right mono text-xs">{fmtNum(r.count)}</td>
                </tr>
                );
              })}
              {n.rejected.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-xs text-fg-subtle">
                    No rejected flows.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>
          </>
        )}

        <VpcFlowLog caseId={caseId} sources={flowSource} vpcId={vpcFilter} />
      </PanelBody>
    </>
  );
}
