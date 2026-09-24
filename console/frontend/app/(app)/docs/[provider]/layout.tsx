import { DOCS_PROVIDER_PARAMS } from "@/lib/static-export-params";
import DocsProviderLayoutClient from "./docs-layout-client";

export function generateStaticParams() {
  return DOCS_PROVIDER_PARAMS;
}

export default function DocsProviderLayout({ children }: { children: React.ReactNode }) {
  return <DocsProviderLayoutClient>{children}</DocsProviderLayoutClient>;
}
