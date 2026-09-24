import { DOCS_COLLECTOR_PARAMS } from "@/lib/static-export-params";

export function generateStaticParams() {
  return DOCS_COLLECTOR_PARAMS;
}

export default function DocsCollectorLayout({ children }: { children: React.ReactNode }) {
  return children;
}
