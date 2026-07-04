"use client";

import { AppShell } from "@/components/layout/app-shell";
import { GlobalSidebar } from "@/components/layout/global-sidebar";
import { TopBar } from "@/components/layout/topbar";
import { usePathname } from "next/navigation";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isCaseWorkspace =
    pathname.startsWith("/cases/") && pathname !== "/cases" && !pathname.endsWith("/settings");

  if (isCaseWorkspace) return children;

  return (
    <AppShell sidebar={<GlobalSidebar />} topbar={<TopBar variant="global" />}>
      {children}
    </AppShell>
  );
}
