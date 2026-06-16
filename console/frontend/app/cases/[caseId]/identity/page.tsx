"use client";

import { useCase } from "@/components/case-context";
import { IdentityKmsTable } from "@/components/identity-kms-table";
import { IdentityRolesTable } from "@/components/identity-roles-table";
import { IdentitySecretsTable } from "@/components/identity-secrets-table";
import { IdentityUsersTable } from "@/components/identity-users-table";
import { PanelBody, PanelHeader } from "@/components/panel";
import { StatCard } from "@/components/stat";
import { LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtNum } from "@/lib/format";
import { useQuery } from "@tanstack/react-query";
import {
  Fingerprint,
  KeyRound,
  Lock,
  Shield,
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
  const kmsKeyList: any[] = kmsQ.data?.data?.keys ?? [];
  const secretsList: any[] = secretsQ.data?.data?.secrets ?? [];
  const kmsKeys = kmsQ.data ? kmsKeyList.length : undefined;
  const secretCount = secretsQ.data ? secretsList.length : undefined;

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

        <div className="cloudtrail-view space-y-4">
          <div className="ct-panel">
            <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
              <KeyRound className="h-4 w-4 text-fg-subtle" />
              <span className="text-sm font-semibold text-fg">IAM users ({users.length})</span>
            </div>
            <IdentityUsersTable users={users} groups={groups} policies={policies} />
          </div>

          <div className="ct-panel">
            <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
              <Shield className="h-4 w-4 text-fg-subtle" />
              <span className="text-sm font-semibold text-fg">IAM roles ({roles.length})</span>
            </div>
            <IdentityRolesTable roles={roles} />
          </div>

          {collected.has("kms") && (
            <div className="ct-panel">
              <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
                <Lock className="h-4 w-4 text-fg-subtle" />
                <span className="text-sm font-semibold text-fg">
                  KMS keys ({kmsKeyList.length})
                </span>
              </div>
              <IdentityKmsTable keys={kmsKeyList} />
            </div>
          )}

          {collected.has("secrets") && (
            <div className="ct-panel">
              <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
                <KeyRound className="h-4 w-4 text-fg-subtle" />
                <span className="text-sm font-semibold text-fg">
                  Secrets ({secretsList.length})
                </span>
              </div>
              <IdentitySecretsTable secrets={secretsList} />
            </div>
          )}
        </div>
      </PanelBody>
    </>
  );
}
