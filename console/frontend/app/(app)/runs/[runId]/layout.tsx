import { RUN_STATIC_PARAMS } from "@/lib/static-export-params";

export function generateStaticParams() {
  return RUN_STATIC_PARAMS;
}

export default function RunIdLayout({ children }: { children: React.ReactNode }) {
  return children;
}
