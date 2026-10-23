"use client";

import { caseHref } from "@/lib/routes";
import { useRouteParam } from "@/lib/use-route-param";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** Legacy route — cases open on the audit timeline, not overview. */
export default function OverviewRedirect() {
  const caseId = useRouteParam("caseId", 1);
  const router = useRouter();
  useEffect(() => {
    if (caseId) router.replace(caseHref(caseId));
  }, [caseId, router]);
  return null;
}
