"use client";

import { Entity } from "@/components/pivot";
import { fmtDateOnly } from "@/lib/format";

export function IdentityKmsTable({ keys }: { keys: any[] }) {
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
            <th>Key ID</th>
            <th>Description</th>
            <th>Usage</th>
            <th>State</th>
            <th>Manager</th>
            <th>Region</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => {
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
