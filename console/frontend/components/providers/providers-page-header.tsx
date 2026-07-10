"use client";

import { KpiMetricCard } from "@/components/stat";
import { Button } from "@/components/ui";
import { CheckCircle2, CloudCog, Plus, TriangleAlert, XCircle } from "lucide-react";

type ProvidersPageHeaderProps = {
  onAdd: () => void;
  total: number;
  connected: number;
  untested: number;
  failed: number;
};

export function ProvidersPageHeader({
  onAdd,
  total,
  connected,
  untested,
  failed,
}: ProvidersPageHeaderProps) {
  return (
    <>
      <div className="mb-8 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="page-title">
            <CloudCog className="h-5 w-5 text-accent" />
            Authentication
          </h1>
        </div>
        <Button variant="primary" icon={Plus} onClick={onAdd}>
          Add connection
        </Button>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiMetricCard label="Saved" value={total} icon={CloudCog} />
        <KpiMetricCard
          label="Healthy"
          value={connected}
          icon={CheckCircle2}
          tone="success"
        />
        <KpiMetricCard
          label="Untested"
          value={untested}
          icon={TriangleAlert}
          tone="high"
        />
        <KpiMetricCard
          label="Failed"
          value={failed}
          icon={XCircle}
          tone="critical"
        />
      </div>
    </>
  );
}
