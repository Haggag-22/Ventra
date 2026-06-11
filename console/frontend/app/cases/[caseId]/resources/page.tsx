"use client";

import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Entity } from "@/components/pivot";
import { Badge, Card, CardHeader, EmptyState, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Database, HardDrive, Server, Share2 } from "lucide-react";
import { useState } from "react";

export default function ResourcesPage() {
  const { caseId } = useCase();
  const [tab, setTab] = useState<"ec2" | "s3">("ec2");
  const q = useQuery({ queryKey: ["resources", caseId], queryFn: () => api.resources(caseId) });

  if (q.isLoading || !q.data) return <LoadingPanel label="Loading resources…" />;
  const ec2 = q.data.ec2 ?? {};
  const s3 = q.data.s3 ?? {};
  const instances: any[] = ec2.instances ?? [];
  const snapshots: any[] = ec2.snapshots ?? [];
  const buckets: any[] = s3.buckets ?? [];
  const sharedSnaps = snapshots.filter((s) => s.Shared || s.OwnerAlias);

  const tabs = [
    { id: "ec2" as const, label: "Compute & storage", icon: Server, count: instances.length + snapshots.length },
    { id: "s3" as const, label: "S3 buckets", icon: Database, count: buckets.length },
  ];

  return (
    <>
      <PanelHeader
        icon={Boxes}
        title="Resources"
        description="Inventory and exposure — what changed or was shared during the window"
      />
      <PanelBody className="space-y-4">
        <div className="flex gap-2">
          {tabs.map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs ${
                  tab === t.id
                    ? "border-accent/40 bg-accent/12 text-accent"
                    : "border-border bg-surface text-fg-subtle hover:text-fg"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {t.label}
                <span className="mono">{t.count}</span>
              </button>
            );
          })}
        </div>

        {tab === "ec2" && (
          <>
            {/* Exfil highlight: shared snapshots first */}
            {sharedSnaps.length > 0 && (
              <Card className="border-high/30">
                <CardHeader
                  title="Shared / exported EBS snapshots"
                  subtitle="Cross-account snapshot sharing is a classic exfiltration pattern"
                  icon={Share2}
                />
                <div className="divide-y divide-border">
                  {sharedSnaps.map((s) => (
                    <div key={s.SnapshotId} className="flex items-center justify-between px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <Entity kind="resource" value={s.SnapshotId} />
                        <Badge className="border-high/30 bg-high/10 text-high">shared</Badge>
                        {s.Encrypted === false && (
                          <Badge className="border-medium/30 bg-medium/10 text-medium">
                            unencrypted
                          </Badge>
                        )}
                      </div>
                      <span className="mono text-2xs text-fg-subtle">
                        {s.VolumeSize ?? s.Size ?? "?"} GiB · {s.Description ?? ""}
                      </span>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            <Card className="overflow-hidden">
              <CardHeader title={`Instances (${instances.length})`} icon={Server} />
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                    <th className="px-4 py-2">Instance</th>
                    <th className="px-4 py-2">Type</th>
                    <th className="px-4 py-2">State</th>
                    <th className="px-4 py-2">Private IP</th>
                    <th className="px-4 py-2">Public IP</th>
                  </tr>
                </thead>
                <tbody>
                  {instances.map((i) => (
                    <tr key={i.InstanceId} className="row-hover border-b border-border/60">
                      <td className="px-4 py-2.5">
                        <Entity kind="resource" value={i.InstanceId} />
                      </td>
                      <td className="px-4 py-2.5 mono text-xs text-fg-subtle">{i.InstanceType}</td>
                      <td className="px-4 py-2.5">
                        <Badge className="border-border bg-surface-2 text-fg-subtle">
                          {i.State?.Name ?? "?"}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        {i.PrivateIpAddress ? <Entity kind="ip" value={i.PrivateIpAddress} /> : "—"}
                      </td>
                      <td className="px-4 py-2.5">
                        {i.PublicIpAddress ? <Entity kind="ip" value={i.PublicIpAddress} /> : "—"}
                      </td>
                    </tr>
                  ))}
                  {instances.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-4 py-6 text-center text-xs text-fg-subtle">
                        No instances collected.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </Card>
          </>
        )}

        {tab === "s3" &&
          (buckets.length === 0 ? (
            <Card className="py-4">
              <EmptyState icon={Database} title="No S3 inventory" description="The s3 collector did not return data for this case." />
            </Card>
          ) : (
            <Card className="overflow-hidden">
              <CardHeader title={`Buckets (${buckets.length})`} icon={HardDrive} />
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-2xs uppercase tracking-wide text-fg-subtle">
                    <th className="px-4 py-2">Bucket</th>
                    <th className="px-4 py-2">Region</th>
                    <th className="px-4 py-2">Exposure</th>
                    <th className="px-4 py-2">Access logging</th>
                  </tr>
                </thead>
                <tbody>
                  {buckets.map((b) => {
                    const pub = b._harbor_public || b.policy_status?.IsPublic;
                    const noLog = b._harbor_no_access_logging || !b.logging;
                    return (
                      <tr key={b.name} className="row-hover border-b border-border/60">
                        <td className="px-4 py-2.5">
                          <Entity kind="resource" value={b.name} />
                        </td>
                        <td className="px-4 py-2.5 mono text-xs text-fg-subtle">{b.region || "—"}</td>
                        <td className="px-4 py-2.5">
                          {pub ? (
                            <Badge className="border-critical/30 bg-critical/10 text-critical">
                              public
                            </Badge>
                          ) : (
                            <Badge className="border-border bg-surface-2 text-fg-subtle">private</Badge>
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          {noLog ? (
                            <Badge className="border-medium/30 bg-medium/10 text-medium">none</Badge>
                          ) : (
                            <span className="text-2xs text-ok-green">enabled</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>
          ))}
      </PanelBody>
    </>
  );
}
