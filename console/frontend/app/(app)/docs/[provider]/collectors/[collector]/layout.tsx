import { docsCollectorStaticParams } from "@/lib/static-export-params";

export function generateStaticParams({
  params,
}: {
  params: { provider: string };
}) {
  return docsCollectorStaticParams(params.provider);
}

export default function DocsCollectorLayout({ children }: { children: React.ReactNode }) {
  return children;
}
