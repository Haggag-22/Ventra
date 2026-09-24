import { CASE_STATIC_PARAMS } from "@/lib/static-export-params";
import CaseLayoutClient from "./case-layout-client";

export function generateStaticParams() {
  return CASE_STATIC_PARAMS;
}

export default function CaseLayout({ children }: { children: React.ReactNode }) {
  return <CaseLayoutClient>{children}</CaseLayoutClient>;
}
