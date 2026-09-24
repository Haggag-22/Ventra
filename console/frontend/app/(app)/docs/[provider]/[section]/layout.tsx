import { DOCS_SECTION_PARAMS } from "@/lib/static-export-params";

export function generateStaticParams() {
  return DOCS_SECTION_PARAMS;
}

export default function DocsSectionLayout({ children }: { children: React.ReactNode }) {
  return children;
}
