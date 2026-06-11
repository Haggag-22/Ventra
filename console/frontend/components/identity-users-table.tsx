"use client";

import { IdentityPrincipal } from "@/components/identity-principal";
import { fmtDateOnly } from "@/lib/format";
import { policiesForUser } from "@/lib/iam-policies";
import { useResizableColumns } from "@/lib/resizable-columns";
import { ShieldCheck, ShieldX } from "lucide-react";

const COLS = [
  { key: "user", label: "User", min: 120 },
  { key: "created", label: "Created", min: 100 },
  { key: "access_keys", label: "Access keys", min: 180 },
  { key: "mfa", label: "MFA", min: 80 },
] as const;

type ColKey = (typeof COLS)[number]["key"];

const DEFAULT_WIDTHS: Record<ColKey, number> = {
  user: 160,
  created: 120,
  access_keys: 320,
  mfa: 90,
};

const WIDTHS_KEY = "harbor.identity-users-table.widths";

export function IdentityUsersTable({
  users,
  groups,
  policies,
}: {
  users: any[];
  groups: any[];
  policies: any[];
}) {
  const { startResize, colPct } = useResizableColumns(COLS, DEFAULT_WIDTHS, WIDTHS_KEY);

  if (users.length === 0) {
    return (
      <div className="px-4 py-16 text-center text-sm text-fg-subtle">No users collected.</div>
    );
  }

  return (
    <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
      <table
        className="ct-table ct-table-no-row-click w-full border-collapse text-left"
        style={{ tableLayout: "fixed" }}
      >
        <colgroup>
          {COLS.map((c) => (
            <col key={c.key} style={{ width: colPct(c.key) }} />
          ))}
        </colgroup>
        <thead className="sticky top-0 z-10">
          <tr>
            {COLS.map((c) => (
              <th key={c.key} className="relative">
                <span className="block truncate pr-2">{c.label}</span>
                <span
                  role="separator"
                  aria-orientation="vertical"
                  aria-label={`Resize ${c.label} column`}
                  onMouseDown={(e) => startResize(c.key, e)}
                  onClick={(e) => e.stopPropagation()}
                  className="ct-col-resize"
                />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const keys = u.AccessKeys ?? [];
            const mfa = (u.MFADevices ?? []).length > 0;

            return (
              <tr key={u.UserName}>
                <td className="truncate">
                  <IdentityPrincipal
                    label={u.UserName}
                    principalType="user"
                    policies={policiesForUser(u, groups)}
                    mono={false}
                  />
                </td>
                <td className="mono truncate text-fg-subtle">{fmtDateOnly(u.CreateDate)}</td>
                <td>
                  <div className="flex flex-col gap-0.5">
                    {keys.map((k: any) => (
                      <span key={k.AccessKeyId} className="mono block truncate text-2xs text-fg-subtle">
                        {k.AccessKeyId} · {k.Status}
                        {k.LastUsed?.LastUsedDate
                          ? ` · used ${fmtDateOnly(k.LastUsed.LastUsedDate)}`
                          : " · never used"}
                      </span>
                    ))}
                    {keys.length === 0 && <span className="text-2xs text-fg-subtle">none</span>}
                  </div>
                </td>
                <td className="truncate">
                  {mfa ? (
                    <span className="flex items-center gap-1 text-2xs text-ok-green">
                      <ShieldCheck className="h-3.5 w-3.5 shrink-0" /> enabled
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-2xs text-warn-amber">
                      <ShieldX className="h-3.5 w-3.5 shrink-0" /> none
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
