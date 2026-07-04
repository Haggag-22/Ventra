"use client";

import { CaseProvider } from "@/components/case-context";
import { AppShell } from "@/components/layout/app-shell";
import { CaseSidebar } from "@/components/layout/case-sidebar";
import { CommandPalette } from "@/components/layout/command-palette";
import { TopBar } from "@/components/layout/topbar";
import { LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const GOTO: Record<string, string> = {
  o: "overview",
  c: "cloudtrail",
  a: "collection",
  i: "identity",
  n: "network",
  f: "search",
};

export default function CaseLayout({ children }: { children: React.ReactNode }) {
  const params = useParams();
  const router = useRouter();
  const caseId = decodeURIComponent(String(params.caseId));
  const [paletteOpen, setPaletteOpen] = useState(false);

  const summary = useQuery({
    queryKey: ["summary", caseId],
    queryFn: () => api.summary(caseId),
  });

  useEffect(() => {
    let lastG = 0;
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      const typing = tag === "INPUT" || tag === "TEXTAREA";
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen(true);
        return;
      }
      if (typing) return;
      if (e.key === "/") {
        e.preventDefault();
        setPaletteOpen(true);
        return;
      }
      if (e.key === "g") {
        lastG = Date.now();
        return;
      }
      if (Date.now() - lastG < 600 && GOTO[e.key]) {
        router.push(`/cases/${caseId}/${GOTO[e.key]}`);
        lastG = 0;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [caseId, router]);

  return (
    <CaseProvider caseId={caseId} summary={summary.data}>
      <AppShell
        sidebar={<CaseSidebar caseId={caseId} />}
        topbar={<TopBar caseId={caseId} summary={summary.data} variant="case" />}
      >
        {summary.isLoading ? <LoadingPanel label="Opening case…" /> : children}
      </AppShell>
      <CommandPalette caseId={caseId} open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </CaseProvider>
  );
}
