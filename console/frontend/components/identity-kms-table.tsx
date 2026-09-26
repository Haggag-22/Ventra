"use client";

import { Entity } from "@/components/pivot";
import { SortLabel, timeValue, useClientSort, type SortValue } from "@/components/sort-header";
import { fmtDateOnly } from "@/lib/format";

const COLS = [
  { key: "key_id", label: "Key ID" },
  { key: "description", label: "Description" },
  { key: "usage", label: "Usage" },
  { key: "state", label: "State" },
  { key: "manager", label: "Manager" },
  { key: "region", label: "Region" },
  { key: "created", label: "Created" },
] as const;

function kmsValue(k: any, key: string): SortValue {
  const m = k.metadata ?? {};
  switch (key) {
    case "key_id":
      return k.key_id ?? m.KeyId;
    case "description":
      return m.Description;
    case "usage":
      return m.KeyUsage;
    case "state":
      return m.KeyState;
    case "manager":
      return m.KeyManager;
    case "region":
      return k.region ?? m._ventra_region;
    case "created":
      return timeValue(m.CreationDate);
    default:
      return null;
  }
}

export function IdentityKmsTable({ keys }: { keys: any[] }) {
  const { sorted, sort, toggle } = useClientSort(keys ?? [], kmsValue);
  if (!keys || keys.length === 0) {
    return (
      <div className="px-4 py-16 text-center text-sm text-fg-subtle">No KMS keys collected.</div>
    );
  }

  return (
    <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
      <table className="ct-table ct-table-no-row-click w-full border-collapse text-left">
        <thead className="sticky top-0 z-10">
          <tr>
            {COLS.map((c) => (
              <th key={c.key}>
                <SortLabel label={c.label} sortKey={c.key} sort={sort} onSort={toggle} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((k) => {
            const m = k.metadata ?? {};
            const region = k.region ?? m._ventra_region ?? "";
            return (
              <tr key={k.key_id ?? m.KeyId}>
                <td className="truncate">
                  <Entity kind="resource" value={k.key_id ?? m.KeyId} truncate />
                </td>
                <td className="truncate text-fg-subtle">{m.Description || "—"}</td>
                <td className="mono text-xs text-fg-subtle">{m.KeyUsage || "—"}</td>
                <td>
                  <span
                    className={
                      m.KeyState === "Enabled"
                        ? "chip border-ok-green/30 bg-ok-green/10 text-ok-green"
                        : "chip"
                    }
                  >
                    {m.KeyState || "—"}
                  </span>
                </td>
                <td className="text-xs text-fg-subtle">{m.KeyManager || "—"}</td>
                <td className="mono text-xs text-fg-subtle">{region || "—"}</td>
                <td className="mono text-xs text-fg-subtle">{fmtDateOnly(m.CreationDate)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
