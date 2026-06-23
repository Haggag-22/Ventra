"use client";

import { useCase } from "@/components/case-context";
import { KubernetesAuditTable } from "@/components/kubernetes-audit-table";
import {
  KubernetesAuditToolbar,
  type K8sAuditFilters,
} from "@/components/kubernetes-audit-toolbar";
import { PanelBody, PanelHeader } from "@/components/panel";
import { TablePager } from "@/components/table-pager";
import { api, type EventParams } from "@/lib/api";
import { caseCloud, kubernetesAuditSources } from "@/lib/cloud-sources";
import {
  ALL_K8S_AUDIT_COL_KEYS,
  K8S_AUDIT_VISIBLE_COLS_KEY,
  loadVisibleK8sAuditCols,
  type K8sAuditColKey,
} from "@/lib/kubernetes-audit-columns";
import { usePagination } from "@/lib/pagination";
import { panelLabel } from "@/lib/panel-labels";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Container } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

const PAGE_SIZE_KEY = "ventra.kubernetes-audit.page-size";

function baseSources(cloud: ReturnType<typeof caseCloud>) {
  return kubernetesAuditSources(cloud);
}

function filtersFromParams(params: EventParams): K8sAuditFilters {
  return {
    q: params.q,
    actions: params.actions,
    severities: params.severity,
    outcomes: params.outcomes,
    regions: params.regions,
    users: params.users,
    order: params.order ?? "desc",
    user: params.user,
    ip: params.ip,
  };
}

function paramsFromFilters(
  filters: K8sAuditFilters,
  cloud: ReturnType<typeof caseCloud>,
): EventParams {
  return {
    q: filters.q,
    source: baseSources(cloud),
    actions: filters.actions,
    severity: filters.severities,
    outcomes: filters.outcomes,
    regions: filters.regions,
    users: filters.users,
    user: filters.user,
    ip: filters.ip,
    sort: "timestamp",
    order: filters.order ?? "desc",
  };
}

export default function KubernetesAuditPage() {
  const { caseId, summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const sources = baseSources(cloud);
  const { params, write, clearAll } = useFilters();
  const { page, setPage, pageSize, setPageSize } = usePagination(PAGE_SIZE_KEY);
  const [visibleColumns, setVisibleColumns] = useState<K8sAuditColKey[]>(ALL_K8S_AUDIT_COL_KEYS);

  useEffect(() => {
    setVisibleColumns(loadVisibleK8sAuditCols());
  }, []);

  const handleColumnsChange = useCallback((cols: K8sAuditColKey[]) => {
    setVisibleColumns(cols);
    try {
      localStorage.setItem(K8S_AUDIT_VISIBLE_COLS_KEY, JSON.stringify(cols));
    } catch {
      /* ignore */
    }
  }, []);

  const filters = useMemo(() => filtersFromParams(params), [params]);
  const effective = useMemo(() => paramsFromFilters(filters, cloud), [filters, cloud]);

  const totalQ = useQuery({
    queryKey: ["k8s-total", caseId, cloud],
    queryFn: () => api.events(caseId, { source: sources, limit: 1, offset: 0 }),
  });

  const eventsQ = useQuery({
    queryKey: ["k8s-events", caseId, effective, page, pageSize],
    queryFn: () =>
      api.events(caseId, { ...effective, limit: pageSize, offset: page * pageSize }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["k8s-facets", caseId, cloud],
    queryFn: () => api.facets(caseId, { source: sources }),
  });

  const matched = eventsQ.data?.total ?? 0;
  const totalAvailable = totalQ.data?.total ?? 0;
  const eventsFailed = totalQ.isError || eventsQ.isError;
  const gcpStub = cloud === "gcp" && totalAvailable === 0 && !totalQ.isLoading;

  const handleChange = useCallback(
    (next: Partial<K8sAuditFilters>) => {
      const merged = { ...filters, ...next };
      write({
        q: merged.q,
        source: sources,
        actions: merged.actions,
        severity: merged.severities,
        outcomes: merged.outcomes,
        regions: merged.regions,
        users: merged.users,
        user: merged.user,
        ip: merged.ip,
        order: merged.order ?? "desc",
        sort: "timestamp",
      });
      setPage(0);
    },
    [filters, write, sources],
  );

  const handleApply = useCallback(() => {
    write({
      user: filters.user,
      ip: filters.ip,
    });
    setPage(0);
  }, [filters, write]);

  const handleReset = useCallback(() => {
    setPage(0);
    clearAll();
  }, [clearAll]);

  return (
    <>
      <PanelHeader
        icon={Container}
        title={panelLabel(cloud, "kubernetes-audit")}
        panel="kubernetes-audit"
      />
      <PanelBody className="cloudtrail-view cloudtrail-events space-y-4">
        {gcpStub && (
          <div className="rounded-lg border border-border bg-surface-2 px-4 py-3 text-sm text-fg-subtle">
            GKE audit log collection is not yet available. Kubernetes API audit events for GCP
            cases will appear here once the <span className="mono">gke_audit</span> collector ships.
          </div>
        )}

        {eventsFailed && (
          <div className="rounded-lg border border-bad-red/30 bg-bad-red/10 px-4 py-3 text-sm text-bad-red">
            Could not load Kubernetes audit events from the case store. Restart the backend after
            upgrading, or re-import the case with <span className="mono">make ingest</span>.
          </div>
        )}

        <KubernetesAuditToolbar
          facets={facetsQ.data}
          filters={filters}
          visibleColumns={visibleColumns}
          onChange={handleChange}
          onColumnsChange={handleColumnsChange}
          onApply={handleApply}
          onReset={handleReset}
        />

        <div className="ct-panel">
          <KubernetesAuditTable
            events={eventsQ.data?.events ?? []}
            loading={eventsQ.isPending && !eventsQ.data}
            visibleColumns={visibleColumns}
          />
        </div>

        <TablePager
          page={page}
          pageSize={pageSize}
          total={matched}
          shown={eventsQ.data?.events.length ?? 0}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      </PanelBody>
    </>
  );
}
