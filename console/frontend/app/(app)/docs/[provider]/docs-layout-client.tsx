"use client";

import { isHiddenUiPlatform } from "@/lib/catalog";
import { docsDefaultHref } from "@/lib/docs-routes";
import { useRouteParam } from "@/lib/use-route-param";
import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

/** Hidden platforms redirect client-side (compatible with static export). */
export default function DocsProviderLayoutClient({ children }: { children: ReactNode }) {
  const provider = useRouteParam("provider", 1);
  const router = useRouter();

  useEffect(() => {
    if (provider && isHiddenUiPlatform(provider)) {
      router.replace(docsDefaultHref());
    }
  }, [provider, router]);

  if (provider && isHiddenUiPlatform(provider)) {
    return null;
  }
  return children;
}
