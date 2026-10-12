"use client";

import { AppShell } from "@/components/layout/app-shell";
import { GlobalSidebar } from "@/components/layout/global-sidebar";
import { isCaseWorkspacePath } from "@/lib/routes";
import { usePathname } from "next/navigation";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  if (isCaseWorkspacePath(pathname)) return children;

  return (
    <AppShell sidebar={<GlobalSidebar />}>
      {children}
    </AppShell>
  );
}
