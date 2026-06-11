"use client";

import { createContext, useContext } from "react";
import type { CaseSummary } from "@/lib/types";

interface CaseCtx {
  caseId: string;
  summary?: CaseSummary;
}

const Ctx = createContext<CaseCtx | null>(null);

export function CaseProvider({ caseId, summary, children }: CaseCtx & { children: React.ReactNode }) {
  return <Ctx.Provider value={{ caseId, summary }}>{children}</Ctx.Provider>;
}

export function useCase(): CaseCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useCase must be used within CaseProvider");
  return c;
}
