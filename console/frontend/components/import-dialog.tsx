"use client";

import { importPackage } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileArchive, FolderOpen, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Button, Input } from "./ui";

type Stage = "idle" | "uploading" | "done" | "error";

const STEPS = ["Verify signature & hashes", "Parse sources", "Normalize events", "Load case"];

function suggestCaseId(filename: string): string {
  const hit = filename.match(/(CASE-[A-Za-z0-9-]+)/i);
  return hit?.[1]?.toUpperCase() ?? "";
}

export function ImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [stage, setStage] = useState<Stage>("idle");
  const [caseName, setCaseName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();
  const qc = useQueryClient();

  useEffect(() => {
    if (!open) return;
    setStage("idle");
    setCaseName("");
    setFile(null);
    setResult(null);
    setError("");
  }, [open]);

  if (!open) return null;

  const pickFile = () => inputRef.current?.click();

  const onFileChange = (next: File | null) => {
    setFile(next);
    setError("");
    if (next && !caseName.trim()) {
      const suggested = suggestCaseId(next.name);
      if (suggested) setCaseName(suggested);
    }
  };

  const handleImport = async () => {
    if (!caseName.trim()) {
      setError("Enter a case name.");
      return;
    }
    if (!file) {
      setError("Choose an evidence package file.");
      return;
    }
    setStage("uploading");
    setError("");
    try {
      const res = await importPackage(file, caseName.trim());
      setResult(res);
      setStage("done");
      qc.invalidateQueries({ queryKey: ["cases"] });
    } catch (e: any) {
      setError(e.message || "Import failed");
      setStage("error");
    }
  };

  const reset = () => {
    setStage("idle");
    setCaseName("");
    setFile(null);
    setResult(null);
    setError("");
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
            <FileArchive className="h-4 w-4 text-accent" /> Import evidence package
          </h3>
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5">
          {stage === "idle" && (
            <>
              <div className="space-y-4">
                <label className="block space-y-1.5">
                  <span className="text-xs font-medium text-fg">Case name</span>
                  <Input
                    value={caseName}
                    onChange={(e) => setCaseName(e.target.value)}
                    placeholder="e.g. CASE-2026-0042"
                    required
                    autoFocus
                  />
                </label>

                <div className="space-y-1.5">
                  <span className="text-xs font-medium text-fg">Evidence package</span>
                  <div className="flex items-center gap-2">
                    <div className="min-w-0 flex-1 truncate rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-fg-subtle">
                      {file ? file.name : "No file selected"}
                    </div>
                    <Button type="button" variant="secondary" icon={FolderOpen} onClick={pickFile}>
                      Browse…
                    </Button>
                  </div>
                  <input
                    ref={inputRef}
                    type="file"
                    accept=".tar.zst,.tar.gz,.zst,.gz,.tar,application/gzip,application/x-gzip"
                    className="hidden"
                    onChange={(e) => onFileChange(e.target.files?.[0] ?? null)}
                  />
                  <span className="text-2xs text-fg-subtle">
                    Harbor evidence archive (.tar.zst or .tar.gz)
                  </span>
                </div>
              </div>

              {error && <p className="mt-3 text-sm text-bad-red">{error}</p>}

              <div className="mt-5 flex justify-end gap-2">
                <Button type="button" variant="ghost" onClick={onClose}>
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="primary-dark"
                  disabled={!file || !caseName.trim()}
                  onClick={handleImport}
                >
                  Import
                </Button>
              </div>
            </>
          )}

          {stage === "uploading" && (
            <div className="space-y-3 py-4">
              {STEPS.map((s) => (
                <div key={s} className="flex items-center gap-3 text-sm">
                  <span className="h-2 w-2 animate-pulse rounded-full bg-accent" />
                  <span className="text-fg-subtle">{s}…</span>
                </div>
              ))}
            </div>
          )}

          {stage === "done" && result && (
            <div className="py-2">
              <div className="flex items-center gap-2 text-ok-green">
                <CheckCircle2 className="h-5 w-5" />
                <span className="text-sm font-medium">Imported {result.case_id}</span>
              </div>
              <dl className="mt-4 space-y-1.5 text-sm">
                <Row k="Events" v={result.events?.toLocaleString()} />
                <Row k="Integrity" v={result.integrity} />
                <Row k="Sources" v={(result.sources_loaded ?? []).join(", ") || "—"} />
                <Row k="Inventory" v={(result.inventory_loaded ?? []).join(", ") || "—"} />
              </dl>
              {result.warnings?.length > 0 && (
                <ul className="mt-3 space-y-1 text-2xs text-warn-amber">
                  {result.warnings.map((w: string, i: number) => (
                    <li key={i}>⚠ {w}</li>
                  ))}
                </ul>
              )}
              <div className="mt-5 flex justify-end gap-2">
                <Button variant="ghost" onClick={reset}>
                  Import another
                </Button>
                <Button
                  variant="primary-dark"
                  onClick={() => router.push(`/cases/${encodeURIComponent(result.case_id)}/overview`)}
                >
                  Open case
                </Button>
              </div>
            </div>
          )}

          {stage === "error" && (
            <div className="py-4">
              <p className="text-sm text-bad-red">{error}</p>
              <div className="mt-4 flex justify-end">
                <Button variant="secondary" onClick={reset}>
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

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-fg-subtle">{k}</dt>
      <dd className="mono text-fg text-right">{v}</dd>
    </div>
  );
}
