"use client";

import { AcquireHandoffDialog } from "@/components/acquire-handoff-dialog";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { KitDownloadWizard } from "@/components/kit-download-wizard";
import { KitRunWizard } from "@/components/kit-run-wizard";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { saveKitHandoff, type KitHandoffRecord } from "@/lib/acquire-handoff";
import {
  buildKitDownloadRequest,
  buildKitRunRequest,
  type KitRunScopeState,
} from "@/lib/acquisition-build";
import {
  buildAcquisitionKit,
  deleteProfile,
  listProfiles,
  previewAcquisitionKit,
  startRun,
  type CollectionProfile,
} from "@/lib/api";
import { CASE_PLATFORM_LABELS, type CasePlatform } from "@/lib/catalog";
import { displayCaseId } from "@/lib/case-id";
import { isEnterpriseProfile, parseDeploymentProfile } from "@/lib/deployment-profiles";
import { handoffModeFromTransport } from "@/lib/handoff-modes";
import {
  CASES_HREF,
  CONFIG_ACQUIRE_HREF,
  CONFIG_COLLECTION_HREF,
  collectionKitEditHref,
  runHref,
} from "@/lib/routes";
import { writeLastConnection } from "@/lib/provider-storage";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, LayoutTemplate, Pencil, Play, Plus, Trash2 } from "lucide-react";
import Link from "next/link";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { useRouter } from "next/navigation";
import { useCallback, useRef, useState } from "react";

function KitRunRow({
  kit,
  onDelete,
  deleting,
  onRun,
  onDownload,
  downloading,
}: {
  kit: CollectionProfile;
  onDelete: () => void;
  deleting: boolean;
  onRun: () => void;
  onDownload: () => void;
  downloading: boolean;
}) {
  const collectorCount = kit.artifacts?.length ?? 0;

  return (
    <tr className="kit-row border-b border-border/60 last:border-0 transition-colors hover:bg-surface-2/30">
      <td className="table-cell font-medium">{displayCaseId(kit.name)}</td>
      <td className="table-cell-center">
        <span className="inline-flex justify-center" title={CASE_PLATFORM_LABELS[kit.cloud as CasePlatform] ?? kit.cloud}>
          <CloudProviderIcon cloud={kit.cloud as CasePlatform} />
        </span>
      </td>
      <td className="table-cell">{collectorCount}</td>
      <td className="table-cell-center">
        <div className="flex flex-wrap items-center justify-center gap-2">
          <Button
            variant="primary"
            size="sm"
            icon={Play}
            disabled={!collectorCount}
            onClick={onRun}
          >
            Run
          </Button>
          <Button
            variant="primary"
            size="sm"
            icon={Download}
            disabled={!collectorCount || downloading}
            loading={downloading}
            onClick={onDownload}
          >
            Download Kit
          </Button>
          <Link href={collectionKitEditHref(kit.id)}>
            <Button variant="secondary" size="sm" icon={Pencil}>
              Edit
            </Button>
          </Link>
          <Button
            variant="ghost"
            size="icon"
            icon={Trash2}
            loading={deleting}
            disabled={deleting}
            onClick={onDelete}
            aria-label={`Delete kit ${kit.name}`}
            title="Delete"
            className="hover:border-bad-red/40 hover:bg-bad-red/10 hover:text-bad-red"
          />
        </div>
      </td>
    </tr>
  );
}

export default function CollectionKitsPage() {
  const router = useRouter();
  const qc = useQueryClient();
  const tableRef = useRef<HTMLDivElement>(null);
  const profiles = useQuery({ queryKey: ["config", "profiles"], queryFn: listProfiles });
  const [runTarget, setRunTarget] = useState<CollectionProfile | null>(null);
  const [downloadTarget, setDownloadTarget] = useState<CollectionProfile | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState("");
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState("");
  const [handoff, setHandoff] = useState<KitHandoffRecord | null>(null);
  const [handoffOpen, setHandoffOpen] = useState(false);

  const delMut = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["config", "profiles"] }),
  });

  const rows = profiles.data?.profiles ?? [];

  const startKitRun = async (payload: {
    caseId: string;
    connectionId: string;
    scope: KitRunScopeState;
  }) => {
    if (!runTarget) return;
    setRunning(true);
    setRunError("");
    try {
      writeLastConnection(payload.connectionId);
      const body = buildKitRunRequest(runTarget, payload.caseId, payload.scope);
      const { run_id } = await startRun({
        ...body,
        connection_id: payload.connectionId.trim() || undefined,
      });
      setRunTarget(null);
      router.push(runHref(run_id));
    } catch (e: unknown) {
      setRunError(e instanceof Error ? e.message : "Failed to start run");
    } finally {
      setRunning(false);
    }
  };

  const downloadKit = useCallback(
    async (kit: CollectionProfile, connectionId: string) => {
      setDownloadingId(kit.id);
      setDownloadError("");
      try {
        writeLastConnection(connectionId);
        const body = buildKitDownloadRequest(kit, connectionId);
        const preview = await previewAcquisitionKit(body);
        await buildAcquisitionKit(body);
        const deploymentProfile = parseDeploymentProfile(kit.deployment_profile);
        const record: KitHandoffRecord = {
          caseId: body.case_id || "CASE-PENDING",
          cloud: kit.cloud,
          collectors: kit.artifacts ?? [],
          deploymentProfile,
          builtAt: new Date().toISOString(),
          ventraVersion: preview.ventra_version,
          includeIam: true,
          ...(isEnterpriseProfile(deploymentProfile)
            ? { handoffMode: handoffModeFromTransport(kit.transport), transport: kit.transport }
            : {}),
        };
        saveKitHandoff(record);
        setHandoff(record);
        setHandoffOpen(true);
        setDownloadTarget(null);
      } catch (e: unknown) {
        setDownloadError(e instanceof Error ? e.message : "Kit build failed");
      } finally {
        setDownloadingId(null);
      }
    },
    [],
  );

  const openImport = useCallback(() => {
    setHandoffOpen(false);
    router.push(`${CASES_HREF}?import_case=${encodeURIComponent(handoff?.caseId || "CASE-PENDING")}`);
  }, [router, handoff?.caseId]);

  const openImportS3 = useCallback(() => {
    setHandoffOpen(false);
    router.push(`${CASES_HREF}?import_s3=1`);
  }, [router]);

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
            Collection Kits
          </h1>
        </div>
        <Link href={CONFIG_ACQUIRE_HREF}>
          <Button variant="primary" icon={Plus}>
            Build kit
          </Button>
        </Link>
      </div>

      {downloadError && (
        <p className="mb-4 text-sm text-bad-red">{downloadError}</p>
      )}

      {profiles.isLoading ? (
        <LoadingPanel label="Loading kits…" />
      ) : rows.length === 0 ? (
        <Card className="p-6">
          <EmptyState
            icon={LayoutTemplate}
            title="No Collection Kits"
            description="Build a cart on Configuration → Acquire, then use Save kit to store it for one-click runs."
            action={
              <Link href={CONFIG_ACQUIRE_HREF}>
                <Button variant="primary">Open Acquire</Button>
              </Link>
            }
          />
        </Card>
      ) : (
        <div ref={tableRef}>
          <Card className="glass-card-glow overflow-hidden">
            <table className="w-full text-sm">
            <thead>
              <tr className="table-head-row">
                <th className="table-header-cell">Name</th>
                <th className="table-header-cell-center">Platform</th>
                <th className="table-header-cell">Collectors</th>
                <th className="table-header-cell-center">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((kit: CollectionProfile) => (
                <KitRunRow
                  key={kit.id}
                  kit={kit}
                  deleting={delMut.isPending && delMut.variables === kit.id}
                  downloading={downloadingId === kit.id}
                  onDelete={() => {
                    if (confirm(`Delete kit "${kit.name}"?`)) delMut.mutate(kit.id);
                  }}
                  onRun={() => {
                    setRunError("");
                    setRunTarget(kit);
                  }}
                  onDownload={() => {
                    setDownloadError("");
                    setDownloadTarget(kit);
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
          Configuration → Scans
        </Link>
        .
      </p>

      <KitDownloadWizard
        open={downloadTarget !== null}
        kit={downloadTarget}
        onClose={() => {
          if (!downloadingId) setDownloadTarget(null);
        }}
        onConfirm={({ connectionId }) => {
          if (downloadTarget) downloadKit(downloadTarget, connectionId);
        }}
        downloading={downloadingId !== null}
        error={downloadError}
      />

      <KitRunWizard
        open={runTarget !== null}
        kit={runTarget}
        onClose={() => {
          if (!running) setRunTarget(null);
        }}
        onConfirm={startKitRun}
        running={running}
        error={runError}
      />

      <AcquireHandoffDialog
        open={handoffOpen}
        handoff={handoff}
        onClose={() => setHandoffOpen(false)}
        onImport={openImport}
        onImportS3={openImportS3}
      />
    </div>
  );
}
