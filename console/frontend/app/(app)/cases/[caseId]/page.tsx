"use client";

import { caseHref } from "@/lib/routes";
import { useRouteParam } from "@/lib/use-route-param";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** `/cases/<id>` opens the default panel. Client-side so the packaged static shell keeps the real ID. */
export default function CaseIndex() {
  const caseId = useRouteParam("caseId", 1);
  const router = useRouter();
  useEffect(() => {
    if (caseId) router.replace(caseHref(caseId));
  }, [caseId, router]);
  return null;
}
