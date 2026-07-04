"use client";

import { PageTransition } from "@/components/layout/page-transition";
import type { ReactNode } from "react";

export function AppShell({
  sidebar,
  topbar,
  children,
}: {
  sidebar: ReactNode;
  topbar?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      {sidebar}
      <div className="flex min-w-0 flex-1 flex-col bg-bg">
        {topbar}
        <main className="flex flex-1 flex-col overflow-y-auto">
          <PageTransition>{children}</PageTransition>
        </main>
      </div>
    </div>
  );
}
