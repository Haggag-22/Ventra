"use client";

import { useCase } from "@/components/case-context";
import { CloudWatchCollectionSummary } from "@/components/cloudwatch-collection-summary";
import { CloudTrailTable } from "@/components/cloudtrail-table";
import {
  CloudTrailToolbar,
  type CloudTrailFilters,
} from "@/components/cloudtrail-toolbar";
import { PanelBody, PanelHeader } from "@/components/panel";
import { nextSort, type SortState } from "@/components/sort-header";
import { TablePager } from "@/components/table-pager";
import { api, type EventParams } from "@/lib/api";
import {
  CLOUDWATCH_VISIBLE_COLS_KEY,
  DEFAULT_CLOUDWATCH_VISIBLE_COLS,
  loadVisibleCloudWatchCols,
  type CloudTrailColKey,
} from "@/lib/cloudtrail-columns";
import { caseCloud, cloudWatchSources } from "@/lib/cloud-sources";
import { panelLabel } from "@/lib/panel-labels";
import { usePagination } from "@/lib/pagination";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Cloud } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

const PAGE_SIZE_KEY = "ventra.cloudwatch.page-size";

function baseSources(cloud: ReturnType<typeof caseCloud>) {
  return cloudWatchSources(cloud);
}

function filtersFromParams(
  params: EventParams,
  cloud: ReturnType<typeof caseCloud>,
): CloudTrailFilters {
  const all = baseSources(cloud);
  const src = params.source ?? [];
  const allSet = new Set(all);
  const isFullDefault =
    src.length === 0 ||
    (src.length === all.length && all.every((s) => src.includes(s)));
  const narrowed =
    !isFullDefault && src.length > 0 && src.every((s) => allSet.has(s));
  return {
    q: params.q,
    actions: params.actions,
    services: params.services,
    regions: params.regions,
    users: params.users,
    sources: narrowed ? src : undefined,
    order: params.order ?? "desc",
    user: params.user,
    ip: params.ip,
  };
}

function paramsFromFilters(
  filters: CloudTrailFilters,
  cloud: ReturnType<typeof caseCloud>,
): EventParams {
  const all = baseSources(cloud);
  const selected = filters.sources?.length
    ? filters.sources.filter((s) => all.includes(s))
    : all;
  return {
    q: filters.q,
    source: selected.length ? selected : all,
    actions: filters.actions,
    services: filters.services,
    regions: filters.regions,
    users: filters.users,
    user: filters.user,
    ip: filters.ip,
    sort: "timestamp",
    order: filters.order ?? "desc",
  };
}

export default function CloudWatchPage() {
  const { caseId, summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const sources = baseSources(cloud);
  const { params, write, clearAll } = useFilters();
  const { page, setPage, pageSize, setPageSize } = usePagination(PAGE_SIZE_KEY);
  const [visibleColumns, setVisibleColumns] = useState<CloudTrailColKey[]>(
    DEFAULT_CLOUDWATCH_VISIBLE_COLS,
  );

  useEffect(() => {
    setVisibleColumns(loadVisibleCloudWatchCols());
  }, []);

  const handleColumnsChange = useCallback((cols: CloudTrailColKey[]) => {
    setVisibleColumns(cols);
    try {
      localStorage.setItem(CLOUDWATCH_VISIBLE_COLS_KEY, JSON.stringify(cols));
    } catch {
      /* ignore */
    }
  }, []);

  const filters = useMemo(() => filtersFromParams(params, cloud), [params, cloud]);
  const effective = useMemo(
    () => ({ ...paramsFromFilters(filters, cloud), sort: params.sort ?? "timestamp" }),
    [filters, cloud, params.sort],
  );
  const sort = useMemo<SortState>(
    () => ({ key: params.sort ?? "timestamp", dir: filters.order === "asc" ? "asc" : "desc" }),
    [params.sort, filters.order],
  );
  const handleSort = useCallback(
    (field: string) => {
      const next = nextSort(sort, field);
      write({ sort: next.key, order: next.dir });
      setPage(0);
    },
    [sort, write, setPage],
  );

  const eventsQ = useQuery({
    queryKey: ["cw-events", caseId, effective, page, pageSize],
    queryFn: () =>
      api.events(caseId, { ...effective, limit: pageSize, offset: page * pageSize }),
    placeholderData: keepPreviousData,
    enabled: sources.length > 0,
  });

  const facetsQ = useQuery({
    queryKey: ["cw-facets", caseId, cloud],
    queryFn: () => api.facets(caseId, { source: sources }),
    enabled: sources.length > 0,
  });

  const matched = eventsQ.data?.total ?? 0;

  const handleChange = useCallback(
    (next: Partial<CloudTrailFilters>) => {
      const merged = { ...filters, ...next };
      const all = baseSources(cloud);
      const selected = merged.sources?.length
        ? merged.sources.filter((s) => all.includes(s))
        : undefined;
      write({
        q: merged.q,
        source: selected?.length ? selected : all,
        actions: merged.actions,
        services: merged.services,
        regions: merged.regions,
        users: merged.users,
        user: merged.user,
        ip: merged.ip,
        order: merged.order ?? "desc",
        sort: params.sort,
      });
      setPage(0);
    },
    [filters, write, cloud, setPage, params.sort],
  );

  const handleApply = useCallback(() => {
    write({ user: filters.user, ip: filters.ip });
    setPage(0);
  }, [filters, write, setPage]);

  const handleReset = useCallback(() => {
    setPage(0);
    clearAll();
  }, [clearAll, setPage]);

  if (cloud !== "aws" || sources.length === 0) {
    return (
      <>
        <PanelHeader icon={Cloud} title={panelLabel(cloud, "cloudwatch")} />
        <PanelBody>
          <div className="rounded-lg border border-border bg-surface-2/40 px-4 py-8 text-center text-sm text-fg-subtle">
            CloudWatch Logs is an AWS investigation panel. Open an AWS case to browse collected
            log groups.
          </div>
        </PanelBody>
      </>
    );
  }

  return (
    <>
      <PanelHeader icon={Cloud} title={panelLabel(cloud, "cloudwatch")} />
      <PanelBody className="cloudtrail-view cloudtrail-events space-y-4">
        <CloudWatchCollectionPanel caseId={caseId} />

        <CloudTrailToolbar
          facets={facetsQ.data}
          filters={filters}
          visibleColumns={visibleColumns}
          cloud={cloud}
          showCategory={false}
          onChange={handleChange}
          onColumnsChange={handleColumnsChange}
          onApply={handleApply}
          onReset={handleReset}
        />

        <div className="ct-panel">
          <CloudTrailTable
            events={eventsQ.data?.events ?? []}
            sort={sort}
            onSort={handleSort}
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

function CloudWatchCollectionPanel({ caseId }: { caseId: string }) {
  const q = useQuery({
    queryKey: ["cw-collection", caseId],
    queryFn: () => api.cloudwatchCollection(caseId),
    retry: 1,
  });

  if (q.isLoading) {
    return (
      <div className="ct-panel px-4 py-6 text-sm text-fg-subtle">
        Loading CloudWatch collection…
      </div>
    );
  }

  if (q.isError || !q.data) return null;

  const hasGroups = (q.data.log_groups?.length ?? 0) > 0 || (q.data.records ?? 0) > 0;
  if (!hasGroups) return null;

  return (
    <div className="ct-panel p-4">
      <CloudWatchCollectionSummary data={q.data} />
    </div>
  );
}
