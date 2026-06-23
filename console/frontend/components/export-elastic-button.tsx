"use client";

import { exportCaseElastic, api } from "@/lib/api";
import { Button } from "@/components/ui";
import { Download } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

export function ExportElasticButton({ caseId }: { caseId: string }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const me = useQuery({ queryKey: ["me"], queryFn: () => api.me() });
  const canExport = (me.data?.capabilities ?? ["export_report"]).includes("export_report");

  if (me.isSuccess && !canExport) {
    return null;
  }

  const onExport = async () => {
    setLoading(true);
    setError("");
    setDone(false);
    try {
      await exportCaseElastic(caseId);
      setDone(true);
    } catch (e: any) {
      setError(e.message || "Export failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        variant="secondary"
        icon={Download}
        className="h-8 text-xs"
        loading={loading}
        disabled={loading}
        onClick={onExport}
      >
        Export to Elastic
      </Button>
      {done && !error && (
        <span className="max-w-xs text-right text-2xs text-ok-green">Export downloaded</span>
      )}
      {error && <span className="max-w-xs text-right text-2xs text-bad-red">{error}</span>}
    </div>
  );
}
