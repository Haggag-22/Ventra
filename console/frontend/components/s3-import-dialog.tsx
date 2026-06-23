"use client";

import { importFromS3, type S3ImportResult } from "@/lib/api";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CloudDownload, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Button, Input } from "./ui";

type Stage = "idle" | "polling" | "done" | "error";

export function S3ImportDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [stage, setStage] = useState<Stage>("idle");
  const [s3Prefix, setS3Prefix] = useState("");
  const [result, setResult] = useState<S3ImportResult | null>(null);
  const [error, setError] = useState("");
  const qc = useQueryClient();
  const router = useRouter();
  const settings = useQuery({
    queryKey: ["enterprise-settings"],
    queryFn: api.enterpriseSettings,
    enabled: open,
  });

  useEffect(() => {
    if (!open) return;
    setStage("idle");
    setResult(null);
    setError("");
    if (settings.data?.ingest_s3_prefix) {
      setS3Prefix(settings.data.ingest_s3_prefix);
    }
  }, [open, settings.data?.ingest_s3_prefix]);

  if (!open) return null;

  const poll = async () => {
    setStage("polling");
    setError("");
    try {
      const res = await importFromS3(s3Prefix);
      setResult(res);
      setStage("done");
      qc.invalidateQueries({ queryKey: ["cases"] });
    } catch (e: any) {
      setError(e.message || "S3 import failed");
      setStage("error");
    }
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4 animate-fade-in"
      onMouseDown={onClose}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <CloudDownload className="h-4 w-4 text-accent" /> Import from S3
          </h3>
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5">
          {stage === "idle" && (
            <>
              <p className="mb-4 text-sm text-fg-subtle">
                Poll your evidence bucket once for new sealed packages. Packages already ingested
                are skipped automatically.
              </p>
              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-fg">S3 prefix</span>
                <Input
                  value={s3Prefix}
                  onChange={(e) => setS3Prefix(e.target.value)}
                  placeholder="s3://evidence-bucket/cases/"
                  className="mono text-sm"
                />
                <span className="text-2xs text-fg-subtle">
                  Default from server env <span className="mono">VENTRA_INGEST_S3_PREFIX</span>
                </span>
              </label>
              {error && <p className="mt-3 text-sm text-bad-red">{error}</p>}
              <div className="mt-5 flex justify-end gap-2">
                <Button type="button" variant="ghost" onClick={onClose}>
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="primary-dark"
                  disabled={!s3Prefix.trim()}
                  onClick={poll}
                >
                  Poll S3 now
                </Button>
              </div>
            </>
          )}

          {stage === "polling" && (
            <div className="space-y-2 py-6 text-center text-sm text-fg-subtle">
              <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-accent" />
              <p>Checking S3 and ingesting new packages…</p>
            </div>
          )}

          {stage === "done" && result && (
            <div className="py-2">
              <div className="flex items-center gap-2 text-ok-green">
                <CheckCircle2 className="h-5 w-5" />
                <span className="text-sm font-medium">
                  {result.ingested.length
                    ? `Ingested ${result.ingested.length} package(s)`
                    : "No new packages found"}
                </span>
              </div>
              {result.skipped > 0 && (
                <p className="mt-2 text-xs text-fg-subtle">
                  Skipped {result.skipped} already ingested object(s).
                </p>
              )}
              {result.ingested.length > 0 && (
                <ul className="mt-3 space-y-2 text-sm">
                  {result.ingested.map((item) => (
                    <li
                      key={item.s3_key}
                      className="rounded border border-border bg-surface-2 px-3 py-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="mono font-medium">{item.case_id}</span>
                        <span className="text-2xs text-fg-subtle">{item.integrity}</span>
                      </div>
                      <p className="mt-1 text-2xs text-fg-subtle">
                        {item.events.toLocaleString()} events
                      </p>
                    </li>
                  ))}
                </ul>
              )}
              {result.errors.length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-bad-red">
                  {result.errors.map((e) => (
                    <li key={e.s3_key}>
                      {e.s3_key}: {e.error}
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-5 flex justify-end gap-2">
                <Button variant="ghost" onClick={() => setStage("idle")}>
                  Poll again
                </Button>
                {result.ingested[0] && (
                  <Button
                    variant="primary-dark"
                    onClick={() =>
                      router.push(
                        `/cases/${encodeURIComponent(result.ingested[0].case_id)}/cloudtrail`,
                      )
                    }
                  >
                    Open case
                  </Button>
                )}
              </div>
            </div>
          )}

          {stage === "error" && (
            <div className="py-4">
              <p className="text-sm text-bad-red">{error}</p>
              <div className="mt-4 flex justify-end">
                <Button variant="secondary" onClick={() => setStage("idle")}>
                  Try again
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
