"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { ProviderSelector } from "@/components/provider-selector";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import {
  deleteProfile,
  listProfiles,
  startRun,
  type AcquisitionBuild,
  type CollectionProfile,
} from "@/lib/api";
import { CASE_PLATFORM_LABELS, type CasePlatform } from "@/lib/catalog";
import {
  CONFIG_ACQUIRE_HREF,
  CONFIG_COLLECTION_HREF,
  collectionKitEditHref,
  runHref,
} from "@/lib/routes";
import { readLastConnection, writeLastConnection } from "@/lib/provider-storage";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LayoutTemplate, Pencil, Play, Plus, Trash2 } from "lucide-react";
import Link from "next/link";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

function profileToRunBody(profile: CollectionProfile): AcquisitionBuild {
  const { id: _id, name: _name, ...body } = profile;
  return body;
}

function KitRunRow({
  kit,
  onDelete,
  deleting,
}: {
  kit: CollectionProfile;
  onDelete: () => void;
  deleting: boolean;
}) {
  const router = useRouter();
  const [connectionId, setConnectionId] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const saved = readLastConnection();
    if (saved) setConnectionId(saved);
  }, []);

  const runKit = async () => {
    setRunning(true);
    setError("");
    try {
      writeLastConnection(connectionId);
      const { run_id } = await startRun({
        ...profileToRunBody(kit),
        connection_id: connectionId.trim() || undefined,
      });
      router.push(runHref(run_id));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to start run");
    } finally {
      setRunning(false);
    }
  };

  return (
    <tr className="kit-row border-b border-border/60 last:border-0 transition-colors hover:bg-surface-2/30">
      <td className="table-cell font-medium">{kit.name}</td>
      <td className="table-cell">
        <span className="inline-flex items-center gap-2">
          <CloudProviderIcon cloud={kit.cloud as CasePlatform} />
          {CASE_PLATFORM_LABELS[kit.cloud as CasePlatform] ?? kit.cloud}
        </span>
      </td>
      <td className="table-cell mono">{kit.case_id}</td>
      <td className="table-cell-muted">{kit.artifacts?.length ?? 0}</td>
      <td className="table-cell">
        <div className="min-w-[12rem] max-w-xs">
          <ProviderSelector
            platform={kit.cloud}
            value={connectionId}
            onChange={setConnectionId}
            label="Provider (optional)"
          />
        </div>
      </td>
      <td className="table-cell-center">
        <div className="flex flex-col items-center gap-2">
          <div className="flex flex-wrap items-center justify-center gap-2">
            <Button
              variant="primary-dark"
              size="sm"
              icon={Play}
              className="bg-accent text-accent-fg hover:bg-accent/90"
              loading={running}
              disabled={running || !(kit.artifacts?.length ?? 0)}
              onClick={runKit}
            >
              Run
            </Button>
            <Link href={collectionKitEditHref(kit.id)}>
              <Button variant="secondary" size="sm" icon={Pencil}>
                Edit
              </Button>
            </Link>
            <Button
              variant="ghost"
              size="sm"
              icon={Trash2}
              loading={deleting}
              disabled={deleting}
              onClick={onDelete}
            />
          </div>
          {error && <p className="text-xs text-bad-red">{error}</p>}
        </div>
      </td>
    </tr>
  );
}

export default function CollectionKitsPage() {
  const qc = useQueryClient();
  const tableRef = useRef<HTMLDivElement>(null);
  const profiles = useQuery({ queryKey: ["config", "profiles"], queryFn: listProfiles });

  const delMut = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["config", "profiles"] }),
  });

  const rows = profiles.data?.profiles ?? [];

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(
        {
          reduceMotion: "(prefers-reduced-motion: reduce)",
          motion: "(prefers-reduced-motion: no-preference)",
        },
        (context) => {
          const reduceMotion = matchMediaReduced(context);
          gsap.from(".kit-row", {
            autoAlpha: reduceMotion ? 1 : 0,
            y: reduceMotion ? 0 : 16,
            duration: reduceMotion ? 0 : 0.35,
            stagger: reduceMotion ? 0 : 0.06,
            ease: "power2.out",
          });
        },
        tableRef,
      );
      return () => mm.revert();
    },
    { scope: tableRef, dependencies: [rows.length], revertOnUpdate: true },
  );

  return (
    <div className="px-6 py-8">
      <div className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="page-title">
            <LayoutTemplate className="h-5 w-5 text-accent" />
            Collection kits
          </h1>
          <p className="page-subtitle">
            Saved acquisition carts — pick a provider, run server-side collection, or edit in Acquire.
          </p>
        </div>
        <Link href={CONFIG_ACQUIRE_HREF}>
          <Button variant="primary-dark" icon={Plus}>
            Build kit
          </Button>
        </Link>
      </div>

      {profiles.isLoading ? (
        <LoadingPanel label="Loading kits…" />
      ) : rows.length === 0 ? (
        <Card className="p-6">
          <EmptyState
            icon={LayoutTemplate}
            title="No saved kits"
            description="Build a cart on Configuration → Acquire, then use Save kit to store it for one-click runs."
            action={
              <Link href={CONFIG_ACQUIRE_HREF}>
                <Button variant="primary-dark">Open Acquire</Button>
              </Link>
            }
          />
        </Card>
      ) : (
        <div ref={tableRef}>
          <Card className="glass-card-glow overflow-hidden">
            <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-surface-2/40">
                <th className="table-header-cell">Name</th>
                <th className="table-header-cell">Platform</th>
                <th className="table-header-cell">Case</th>
                <th className="table-header-cell">Collectors</th>
                <th className="table-header-cell">Provider</th>
                <th className="table-header-cell-center">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((kit: CollectionProfile) => (
                <KitRunRow
                  key={kit.id}
                  kit={kit}
                  deleting={delMut.isPending && delMut.variables === kit.id}
                  onDelete={() => {
                    if (confirm(`Delete kit "${kit.name}"?`)) delMut.mutate(kit.id);
                  }}
                />
              ))}
            </tbody>
          </table>
          </Card>
        </div>
      )}

      <p className="mt-4 text-xs text-fg-subtle">
        Monitor active jobs on{" "}
        <Link href={CONFIG_COLLECTION_HREF} className="text-accent hover:underline">
          Configuration → Collection
        </Link>
        .
      </p>
    </div>
  );
}
