import { isHiddenUiPlatform } from "@/lib/catalog";
import { docsDefaultHref } from "@/lib/docs-routes";
import { redirect } from "next/navigation";
import type { ReactNode } from "react";

/** Hidden platforms (currently Kubernetes) redirect instead of rendering stale docs. */
export default function DocsProviderLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: { provider: string };
}) {
  if (isHiddenUiPlatform(params.provider)) {
    redirect(docsDefaultHref());
  }
  return children;
}
