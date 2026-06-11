"use client";

import { useCase } from "@/components/case-context";
import { IdentityPrincipal } from "@/components/identity-principal";
import { PanelBody, PanelHeader } from "@/components/panel";
import { StatCard } from "@/components/stat";
import { Badge, Card, CardHeader, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtDateOnly, fmtNum } from "@/lib/format";
import { policiesForRole, policiesForUser } from "@/lib/iam-policies";
import { useQuery } from "@tanstack/react-query";
import {
  Fingerprint,
  KeyRound,
  Lock,
  Shield,
  ShieldCheck,
  ShieldX,
  Users,
  UsersRound,
} from "lucide-react";

function countUnusedActiveKeys(users: any[]): number {
  return users.filter((u) =>
    (u.AccessKeys ?? []).some(
      (k: any) => k.Status === "Active" && !(k.LastUsed?.LastUsedDate),
    ),
  ).length;
}

export default function IdentityPage() {
  const { caseId, summary } = useCase();
  const collected = new Set(summary?.collection?.collected ?? []);
  const q = useQuery({ queryKey: ["identity", caseId], queryFn: () => api.identity(caseId) });
  const kmsQ = useQuery({
    queryKey: ["inventory", caseId, "kms"],
    queryFn: () => api.inventory(caseId, "kms"),
    enabled: collected.has("kms"),
  });
  const secretsQ = useQuery({
    queryKey: ["inventory", caseId, "secrets"],
    queryFn: () => api.inventory(caseId, "secrets"),
    enabled: collected.has("secrets"),
  });

  if (q.isLoading || !q.data) return <LoadingPanel label="Loading identity…" />;
  const iam = q.data.iam ?? {};
  const users: any[] = iam.users ?? [];
  const roles: any[] = iam.roles ?? [];
  const groups: any[] = iam.groups ?? [];
  const policies: any[] = iam.policies ?? [];
  const noMfa = users.filter((u) => !(u.MFADevices ?? []).length).length;
  const unusedKeyUsers = countUnusedActiveKeys(users);
  const kmsKeys = kmsQ.data?.data?.keys?.length;
  const secretCount = secretsQ.data?.data?.secrets?.length;

  const keyAgeDays = (d: string) => {
    if (!d) return null;
    return Math.floor((Date.now() - new Date(d).getTime()) / 86400000);
  };

  return (
    <>
      <PanelHeader
        icon={Fingerprint}
        title="Identity & Access"
        panel="identity"
      />
      <PanelBody className="space-y-6">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {collected.has("iam") && (
            <>
              <StatCard label="Users" value={fmtNum(users.length)} icon={Users} />
              <StatCard label="Roles" value={fmtNum(roles.length)} icon={Shield} />
              <StatCard label="Groups" value={fmtNum(groups.length)} icon={UsersRound} />
              <StatCard label="Policies" value={fmtNum(policies.length)} icon={KeyRound} />
              <StatCard
                label="No MFA"
                value={fmtNum(noMfa)}
                icon={ShieldX}
                tone={noMfa > 0 ? "high" : "default"}
                sub={unusedKeyUsers > 0 ? `${fmtNum(unusedKeyUsers)} with unused keys` : undefined}
              />
            </>
          )}
          {collected.has("kms") && kmsKeys !== undefined && (
            <StatCard label="KMS keys" value={fmtNum(kmsKeys)} icon={Lock} />
          )}
          {collected.has("secrets") && secretCount !== undefined && (
            <StatCard label="Secrets" value={fmtNum(secretCount)} icon={KeyRound} />
          )}
        </div>

        {/* IAM users */}
        <Card className="overflow-hidden">
          <CardHeader title={`IAM users (${users.length})`} icon={KeyRound} />
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                <th className="px-4 py-2">User</th>
                <th className="px-4 py-2">Created</th>
                <th className="px-4 py-2">Access keys</th>
                <th className="px-4 py-2">MFA</th>
                <th className="px-4 py-2">Flags</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const keys = u.AccessKeys ?? [];
                const mfa = (u.MFADevices ?? []).length > 0;
                const unusedActive = keys.some(
                  (k: any) => k.Status === "Active" && !(k.LastUsed?.LastUsedDate),
                );
                const newish = keyAgeDays(u.CreateDate);
                return (
                  <tr key={u.UserName} className="row-hover border-b border-border/60">
                    <td className="px-4 py-2.5">
                      <IdentityPrincipal
                        label={u.UserName}
                        principalType="user"
                        policies={policiesForUser(u, groups)}
                        mono={false}
                      />
                    </td>
                    <td className="px-4 py-2.5 mono text-xs text-fg-subtle">
                      {fmtDateOnly(u.CreateDate)}
                      {newish !== null && newish < 7 && (
                        <Badge className="ml-2 border-high/30 bg-high/10 text-high">new</Badge>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-col gap-0.5">
                        {keys.map((k: any) => (
                          <span key={k.AccessKeyId} className="mono text-2xs text-fg-subtle">
                            {k.AccessKeyId} · {k.Status}
                            {k.LastUsed?.LastUsedDate
                              ? ` · used ${fmtDateOnly(k.LastUsed.LastUsedDate)}`
                              : " · never used"}
                          </span>
                        ))}
                        {keys.length === 0 && <span className="text-2xs text-fg-subtle">none</span>}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      {mfa ? (
                        <span className="flex items-center gap-1 text-2xs text-ok-green">
                          <ShieldCheck className="h-3.5 w-3.5" /> enabled
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-2xs text-warn-amber">
                          <ShieldX className="h-3.5 w-3.5" /> none
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {!mfa && (
                          <Badge className="border-warn-amber/30 bg-warn-amber/10 text-warn-amber">
                            no MFA
                          </Badge>
                        )}
                        {unusedActive && (
                          <Badge className="border-medium/30 bg-medium/10 text-medium">
                            unused active key
                          </Badge>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>

        {/* Roles */}
        <Card className="overflow-hidden">
          <CardHeader title={`IAM roles (${roles.length})`} />
          <div className="divide-y divide-border">
            {roles.map((r) => (
              <div key={r.RoleName} className="flex items-center justify-between px-4 py-2.5">
                <IdentityPrincipal
                  label={r.Arn ?? r.RoleName}
                  principalType="role"
                  policies={policiesForRole(r)}
                />
                <span className="mono text-2xs text-fg-subtle">{fmtDateOnly(r.CreateDate)}</span>
              </div>
            ))}
            {roles.length === 0 && (
              <div className="px-4 py-6 text-center text-xs text-fg-subtle">No roles collected.</div>
            )}
          </div>
        </Card>
      </PanelBody>
    </>
  );
}
