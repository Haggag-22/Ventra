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
import { caseCloud } from "@/lib/cloud-sources";
import { fmtNum } from "@/lib/format";
import { panelLabel } from "@/lib/panel-labels";
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
  const cloud = caseCloud(summary?.cloud);
  const collected = new Set(summary?.collection?.collected ?? []);
  const hasIdentitySnapshot =
    collected.has("iam") ||
    collected.has("rbac") ||
    collected.has("entra_directory") ||
    collected.has("iam_policy") ||
    collected.has("k8s_rbac");
  const isGcpIam = collected.has("iam_policy") && !collected.has("iam");
  // A cluster has no IAM: the principals are ServiceAccounts and the roles are
  // (Cluster)Roles, so the headings say so rather than mislabelling them as IAM.
  const isK8sRbac = cloud === "kubernetes";
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
  const applications: any[] = iam.applications ?? [];
  const servicePrincipals: any[] = iam.service_principals ?? [];
  const roles: any[] = iam.roles ?? [];
  const groups: any[] = iam.groups ?? [];
  const policies: any[] = iam.policies ?? [];
  const isAzureDirectory = iam.source === "entra_directory";
  const principalsLabel = isAzureDirectory
    ? "Directory principals"
    : isK8sRbac
      ? "ServiceAccounts"
      : isGcpIam
        ? "Service accounts"
        : "IAM users";
  const rolesLabel = isAzureDirectory
    ? "Role assignments"
    : isK8sRbac
      ? "Roles & ClusterRoles"
      : isGcpIam
        ? "Custom roles"
        : "IAM roles";
  const directoryPrincipals = isAzureDirectory
    ? [...users, ...applications, ...servicePrincipals, ...groups]
    : users;
  const mfaKnown = !isAzureDirectory || iam.mfa_known === true;
  const noMfa = !mfaKnown || isGcpIam ? 0 : users.filter((u) => !(u.MFADevices ?? []).length).length;
  const unusedKeyUsers = countUnusedActiveKeys(users);
  const kmsKeyList: any[] = kmsQ.data?.data?.keys ?? [];
  const secretsList: any[] = secretsQ.data?.data?.secrets ?? [];
  const kmsKeys = kmsQ.data ? kmsKeyList.length : undefined;
  const secretCount = secretsQ.data ? secretsList.length : undefined;

  return (
    <>
      <PanelHeader
        icon={Fingerprint}
        title={panelLabel(cloud, "identity")}
        panel="identity"
      />
      <PanelBody className="space-y-6">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {hasIdentitySnapshot && (
            <>
              <StatCard
                label={isGcpIam ? "Service accounts" : "Users"}
                value={fmtNum(users.length)}
                icon={Users}
              />
              {isAzureDirectory ? (
                <>
                  <StatCard label="Applications" value={fmtNum(applications.length)} icon={KeyRound} />
                  <StatCard
                    label="Service principals"
                    value={fmtNum(servicePrincipals.length)}
                    icon={Fingerprint}
                  />
                  <StatCard label="Groups" value={fmtNum(groups.length)} icon={UsersRound} />
                  <StatCard label="Role assignments" value={fmtNum(roles.length)} icon={Shield} />
                </>
              ) : (
                <>
              <StatCard
                label={isGcpIam ? "Custom roles" : "Roles"}
                value={fmtNum(roles.length)}
                icon={Shield}
              />
              {!isGcpIam && (
                <StatCard label="Groups" value={fmtNum(groups.length)} icon={UsersRound} />
              )}
              <StatCard
                label={isGcpIam ? "Bindings" : "Policies"}
                value={fmtNum(policies.length)}
                icon={KeyRound}
              />
                </>
              )}
              {!isGcpIam && !isAzureDirectory && (
                <StatCard
                  label="No MFA"
                  value={fmtNum(noMfa)}
                  icon={ShieldX}
                  tone={noMfa > 0 ? "high" : "default"}
                  sub={unusedKeyUsers > 0 ? `${fmtNum(unusedKeyUsers)} with unused keys` : undefined}
                />
              )}
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
              <span className="text-sm font-semibold text-fg">
                {`${principalsLabel} (${directoryPrincipals.length})`}
              </span>
            </div>
            <IdentityUsersTable
              users={directoryPrincipals}
              groups={groups}
              policies={policies}
              layout={isAzureDirectory ? "directory" : "iam"}
            />
          </div>

          <div className="ct-panel">
            <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
              <Shield className="h-4 w-4 text-fg-subtle" />
              <span className="text-sm font-semibold text-fg">
                {`${rolesLabel} (${roles.length})`}
              </span>
            </div>
            <IdentityRolesTable roles={roles} layout={isAzureDirectory ? "assignment" : "iam"} />
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
