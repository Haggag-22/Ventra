"use client";

import type { GraphEdge, GraphNode } from "@/lib/types";
import { useState } from "react";

/**
 * Role-assumption graph. A deterministic bipartite layout (principals left, roles right) keeps
 * it readable without a physics simulation dependency. Edge thickness encodes call volume.
 */
export function RoleGraph({
  nodes,
  edges,
  height = 360,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  height?: number;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const principals = nodes.filter((n) => n.type === "principal");
  const roles = nodes.filter((n) => n.type === "role");

  if (nodes.length === 0) {
    return (
      <div className="flex h-[200px] items-center justify-center text-sm text-fg-subtle">
        No AssumeRole activity in this case.
      </div>
    );
  }

  const W = 760;
  const leftX = 150;
  const rightX = W - 150;
  const maxW = Math.max(...edges.map((e) => e.weight), 1);

  const yOf = (list: GraphNode[], idx: number) =>
    list.length === 1 ? height / 2 : 40 + (idx * (height - 80)) / (list.length - 1);

  const pos: Record<string, { x: number; y: number }> = {};
  principals.forEach((n, i) => (pos[n.id] = { x: leftX, y: yOf(principals, i) }));
  roles.forEach((n, i) => (pos[n.id] = { x: rightX, y: yOf(roles, i) }));

  const isActive = (id: string) =>
    !hover ||
    hover === id ||
    edges.some(
      (e) => (e.source === hover && e.target === id) || (e.target === hover && e.source === id),
    );

  return (
    <svg viewBox={`0 0 ${W} ${height}`} width="100%" height={height} className="select-none">
      {/* edges */}
      {edges.map((e, i) => {
        const a = pos[e.source];
        const b = pos[e.target];
        if (!a || !b) return null;
        const active = !hover || hover === e.source || hover === e.target;
        const midX = (a.x + b.x) / 2;
        return (
          <path
            key={i}
            d={`M ${a.x} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${b.x} ${b.y}`}
            fill="none"
            stroke="rgb(var(--accent))"
            strokeOpacity={active ? 0.5 : 0.1}
            strokeWidth={1 + (e.weight / maxW) * 4}
          />
        );
      })}

      {/* nodes */}
      {[...principals, ...roles].map((n) => {
        const p = pos[n.id];
        const active = isActive(n.id);
        const isPrincipal = n.type === "principal";
        return (
          <g
            key={n.id}
            transform={`translate(${p.x}, ${p.y})`}
            opacity={active ? 1 : 0.25}
            onMouseEnter={() => setHover(n.id)}
            onMouseLeave={() => setHover(null)}
            className="cursor-pointer"
          >
            <circle
              r={7}
              fill={isPrincipal ? "rgb(var(--sev-low))" : "rgb(var(--accent))"}
              stroke="rgb(var(--bg))"
              strokeWidth={2}
            />
            <text
              x={isPrincipal ? -12 : 12}
              y={4}
              textAnchor={isPrincipal ? "end" : "start"}
              fontSize={11}
              className="mono"
              fill="rgb(var(--fg))"
            >
              {n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label}
            </text>
          </g>
        );
      })}

      {/* legend */}
      <g transform="translate(16, 16)" fontSize={10} fill="rgb(var(--fg-subtle))">
        <circle cx={4} cy={-3} r={4} fill="rgb(var(--sev-low))" />
        <text x={12} y={0}>principal</text>
        <circle cx={70} cy={-3} r={4} fill="rgb(var(--accent))" />
        <text x={78} y={0}>role</text>
      </g>
    </svg>
  );
}
