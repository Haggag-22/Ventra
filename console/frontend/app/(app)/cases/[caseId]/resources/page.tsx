"use client";

import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { ResourceInventoryTable } from "@/components/resource-inventory-table";
import { Card, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtNum } from "@/lib/format";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Boxes } from "lucide-react";

export default function ResourcesPage() {
  const { caseId } = useCase();
  const summaryQ = useQuery({
    queryKey: ["inventory-summary", caseId],
    queryFn: () => api.inventorySummary(caseId),
  });

  const sources = summaryQ.data?.sources ?? [];
  const inventoryQs = useQueries({
    queries: sources.map((source) => ({
      queryKey: ["inventory", caseId, source],
      queryFn: () => api.inventory(caseId, source),
    })),
  });

  const inventoryBySource = Object.fromEntries(
    sources.map((source, i) => [source, inventoryQs[i]?.data?.data]),
  );

  const inventoryLoading = summaryQ.isLoading || inventoryQs.some((q) => q.isLoading);

  if (inventoryLoading || !summaryQ.data) {
    return <LoadingPanel label="Loading resource inventory…" />;
  }

  const { categories, total_resources } = summaryQ.data;
  const hasAny = sources.length > 0;

  return (
    <>
      <PanelHeader
        icon={Boxes}
        panel="resources"
        title="Resource Inventory"
        description="Resources"
        actions={
          hasAny ? (
            <span className="text-xs text-fg-subtle">
              <span className="font-medium text-accent">{fmtNum(total_resources)}</span> resources
              across {sources.length} snapshot{sources.length === 1 ? "" : "s"}
            </span>
          ) : undefined
        }
      />
      <PanelBody className="cloudtrail-view space-y-6">
        {!hasAny && (
          <Card className="py-4">
            <EmptyState
              icon={Boxes}
              title="No inventory snapshots"
              description="Re-ingest the evidence package after collectors such as ec2, s3, or iam have run."
            />
          </Card>
        )}

        {categories.map((cat) => {
          const collected = cat.items.filter((i) => i.collected);
          if (collected.length === 0) return null;

          return (
            <section key={cat.name} className="space-y-3">
              <h2 className="text-sm font-semibold text-fg">{cat.name}</h2>
              <div className="space-y-3">
                {collected.map((item) => (
                  <ResourceInventoryTable
                    key={item.id}
                    item={item}
                    data={inventoryBySource[item.source]}
                  />
                ))}
              </div>
            </section>
          );
        })}
      </PanelBody>
    </>
  );
}
