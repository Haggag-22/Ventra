"use client";

import { useCase } from "@/components/case-context";
import { catalogItem, PANEL_COLLECTORS, type PanelId } from "@/lib/panel-collectors";
import type { Cloud } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import { Layers } from "lucide-react";

export function PanelCollectors({ panel }: { panel: PanelId }) {
  const { summary } = useCase();
  const def = PANEL_COLLECTORS[panel];
  const cloud = (summary?.cloud ?? "aws") as Cloud;
  const collected = new Set(summary?.collection?.collected ?? []);
  const gapByName = new Map((summary?.collection?.gaps ?? []).map((g) => [g.name, g]));

  if (panel === "collection") {
    return (
      <div className="panel-collectors">
        <Layers className="panel-collectors-icon" aria-hidden />
        <span className="panel-collectors-label">Collectors</span>
      </div>
    );
  }

  return (
    <div className="panel-collectors">
      <Layers className="panel-collectors-icon" aria-hidden />
      <span className="panel-collectors-label">Collectors</span>
      <div className="panel-collectors-chips">
        {def.collectors.map((ref) => {
          const item = catalogItem(cloud, ref.id);
          const ok = collected.has(ref.id);
          const gap = gapByName.get(ref.id);
          const title = [
            item?.description ?? ref.id,
            ok ? "Collected in this case" : gap?.detail ?? "Not collected",
          ]
            .filter(Boolean)
            .join(" · ");

          return (
            <span
              key={ref.id}
              className={cn("panel-collector-chip", ok ? "is-collected" : "is-missing")}
              title={title}
            >
              <span
                className={cn("panel-collector-dot", ok ? "bg-ok-green" : "bg-warn-amber")}
                aria-hidden
              />
              {item?.label ?? ref.id}
            </span>
          );
        })}
      </div>
    </div>
  );
}
