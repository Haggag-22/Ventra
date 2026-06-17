"use client";

import { useCase } from "@/components/case-context";
import { CloudTrailCollectionSummary } from "@/components/cloudtrail-collection-summary";
import { CloudTrailTable } from "@/components/cloudtrail-table";
import { CloudTrailToolbar,
  type CloudTrailFilters,
} from "@/components/cloudtrail-toolbar";
import { PanelBody, PanelHeader } from "@/components/panel";
import { api, type EventParams } from "@/lib/api";
import {
  ALL_CLOUDTRAIL_COL_KEYS,
  CLOUDTRAIL_VISIBLE_COLS_KEY,
  loadVisibleCloudTrailCols,
  type CloudTrailColKey,
} from "@/lib/cloudtrail-columns";
import { usePagination } from "@/lib/pagination";
import { caseCloud, controlPlaneSources } from "@/lib/cloud-sources";
import { panelLabel } from "@/lib/panel-labels";
import { TablePager } from "@/components/table-pager";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

const PAGE_SIZE_KEY = "ventra.cloudtrail.page-size";

function baseSources(cloud: ReturnType<typeof caseCloud>) {
  return controlPlaneSources(cloud);
}

function filtersFromParams(params: EventParams): CloudTrailFilters {
  return {
    q: params.q,
    actions: params.actions,
    services: params.services,
    regions: params.regions,
    users: params.users,
    trailCategories: params.trail_category,
    order: params.order ?? "desc",
    user: params.user,
    ip: params.ip,
  };
}

function paramsFromFilters(filters: CloudTrailFilters, cloud: ReturnType<typeof caseCloud>): EventParams {
  return {
    q: filters.q,
    source: baseSources(cloud),
    actions: filters.actions,
    services: filters.services,
    regions: filters.regions,
    users: filters.users,
    trail_category: filters.trailCategories,
    user: filters.user,
    ip: filters.ip,
    sort: "timestamp",
    order: filters.order ?? "desc",
  };
}

export default function CloudTrailPage() {
  const { caseId, summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const { params, write, clearAll } = useFilters();
  const { page, setPage, pageSize, setPageSize } = usePagination(PAGE_SIZE_KEY);
  const [visibleColumns, setVisibleColumns] = useState<CloudTrailColKey[]>(
    ALL_CLOUDTRAIL_COL_KEYS,
  );

  useEffect(() => {
    setVisibleColumns(loadVisibleCloudTrailCols());
  }, []);

  const handleColumnsChange = useCallback((cols: CloudTrailColKey[]) => {
    setVisibleColumns(cols);
    try {
      localStorage.setItem(CLOUDTRAIL_VISIBLE_COLS_KEY, JSON.stringify(cols));
    } catch {
      /* ignore */
    }
  }, []);

  const filters = useMemo(() => filtersFromParams(params), [params]);
  const effective = useMemo(() => paramsFromFilters(filters, cloud), [filters, cloud]);

  const totalQ = useQuery({
    queryKey: ["ct-total", caseId, cloud],
    queryFn: () => api.events(caseId, { source: baseSources(cloud), limit: 1, offset: 0 }),
  });

  const eventsQ = useQuery({
    queryKey: ["ct-events", caseId, effective, page, pageSize],
    queryFn: () =>
      api.events(caseId, { ...effective, limit: pageSize, offset: page * pageSize }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["ct-facets", caseId, cloud],
    queryFn: () => api.facets(caseId, { source: baseSources(cloud) }),
  });

  const matched = eventsQ.data?.total ?? 0;
  const eventsFailed = totalQ.isError || eventsQ.isError;

  const handleChange = useCallback(
    (next: Partial<CloudTrailFilters>) => {
      const merged = { ...filters, ...next };
      write({
        q: merged.q,
        source: baseSources(cloud),
        actions: merged.actions,
        services: merged.services,
        regions: merged.regions,
        users: merged.users,
        trail_category: merged.trailCategories,
        user: merged.user,
        ip: merged.ip,
        order: merged.order ?? "desc",
        sort: "timestamp",
      });
      setPage(0);
    },
    [filters, write, cloud],
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
      <PanelHeader icon={ScrollText} title={panelLabel(cloud, "cloudtrail")} panel="cloudtrail" />
      <PanelBody className="cloudtrail-view cloudtrail-timeline space-y-4">
        {cloud === "aws" && <CloudTrailCollectionPanel caseId={caseId} />}

        {eventsFailed && (
          <div className="rounded-lg border border-bad-red/30 bg-bad-red/10 px-4 py-3 text-sm text-bad-red">
            Could not load CloudTrail events from the case store. Restart the backend after upgrading,
            or re-import the case with <span className="mono">make ingest</span>.
          </div>
        )}

        <CloudTrailToolbar
          facets={facetsQ.data}
          filters={filters}
          visibleColumns={visibleColumns}
          onChange={handleChange}
          onColumnsChange={handleColumnsChange}
          onApply={handleApply}
          onReset={handleReset}
        />

        <div className="ct-panel">
          <CloudTrailTable
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

function CloudTrailCollectionPanel({ caseId }: { caseId: string }) {
  const q = useQuery({
    queryKey: ["ct-collection", caseId],
    queryFn: () => api.cloudtrailCollection(caseId),
    retry: 1,
  });

  if (q.isLoading) {
    return (
      <div className="ct-panel px-4 py-6 text-sm text-fg-subtle">Loading CloudTrail collection…</div>
    );
  }

  if (q.isError || !q.data) {
    return null;
  }

  const hasTrails = (q.data.trails?.length ?? 0) > 0;
  const hasEvents =
    (q.data.events?.lookup_api?.total ?? 0) > 0 || (q.data.events?.s3?.total ?? 0) > 0;
  if (!hasTrails && !hasEvents) {
    return null;
  }

  return (
    <div className="ct-panel p-4">
      <CloudTrailCollectionSummary data={q.data} />
    </div>
  );
}
