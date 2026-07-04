"use client";

import { listConnections } from "@/lib/api";
import { CONFIG_PROVIDERS_HREF } from "@/lib/routes";
import { useQuery } from "@tanstack/react-query";
import { Cloud } from "lucide-react";
import Link from "next/link";

type ProviderSelectorProps = {
  platform: string;
  value: string;
  onChange: (connectionId: string) => void;
  className?: string;
  label?: string;
};

export function ProviderSelector({
  platform,
  value,
  onChange,
  className,
  label = "Provider",
}: ProviderSelectorProps) {
  const providers = useQuery({
    queryKey: ["config", "connections"],
    queryFn: listConnections,
    staleTime: 60_000,
  });

  const rows = (providers.data?.connections ?? []).filter((c) => c.platform === platform);

  return (
    <label className={className ?? "block space-y-1.5"}>
      <span className="flex items-center gap-1.5 text-sm font-medium text-fg">
        <Cloud className="h-3.5 w-3.5 text-accent" aria-hidden />
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={providers.isLoading}
        className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm"
      >
        <option value="">None (ambient credentials)</option>
        {rows.map((conn) => (
          <option key={conn.id} value={conn.id}>
            {conn.name}
            {conn.profile_name ? ` — ${conn.profile_name}` : ""}
            {conn.project ? ` — ${conn.project}` : ""}
            {conn.subscription ? ` — ${conn.subscription}` : ""}
          </option>
        ))}
      </select>
      {!providers.isLoading && rows.length === 0 && (
        <p className="text-xs text-fg-subtle">
          No providers for this platform.{" "}
          <Link href={CONFIG_PROVIDERS_HREF} className="text-accent hover:underline">
            Add one in Configuration → Providers
          </Link>
          .
        </p>
      )}
    </label>
  );
}
