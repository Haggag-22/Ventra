"use client";

import { isHiddenUiPlatform } from "@/lib/catalog";
import { docsDefaultHref } from "@/lib/docs-routes";
import { useParams, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

/** Hidden platforms redirect client-side (compatible with static export). */
export default function DocsProviderLayoutClient({ children }: { children: ReactNode }) {
  const params = useParams();
  const router = useRouter();
  const provider = String(params?.provider || "");

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
