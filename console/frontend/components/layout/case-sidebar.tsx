"use client";

import { useCase } from "@/components/case-context";
import { BackToCases } from "@/components/layout/back-to-cases";
import { caseCloud } from "@/lib/cloud-sources";
import { panelLabel } from "@/lib/panel-labels";
import { CASES_HREF } from "@/lib/routes";
import { cn } from "@/lib/utils";
import {
  Cloud,
  Container,
  Database,
  FileText,
  Fingerprint,
  Gauge,
  Globe2,
  ListChecks,
  Network,
  ScrollText,
  Shield,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { LucideIcon } from "lucide-react";

type NavEntry = {
  href: string;
  label?: string;
  panel?: Parameters<typeof panelLabel>[1];
  icon: LucideIcon;
  soon?: boolean;
};

const INVESTIGATE: NavEntry[] = [
  { href: "cloudtrail", panel: "cloudtrail", icon: ScrollText },
  { href: "cloudwatch", panel: "cloudwatch", icon: Cloud },
  { href: "search", panel: "search", icon: ShieldAlert },
  { href: "identity", panel: "identity", icon: Fingerprint },
  { href: "network", panel: "network", icon: Network },
  { href: "web", panel: "web", icon: Globe2 },
  { href: "kubernetes-audit", panel: "kubernetes-audit", icon: Container },
  { href: "data-access", panel: "data-access", icon: Database },
  { href: "collection", panel: "collection", icon: ListChecks },
];

const PACKAGE: NavEntry[] = [
  { href: "resources", panel: "resources", icon: Gauge },
  { href: "report", panel: "report", icon: FileText },
  { href: "files", panel: "files", icon: FileText },
];

function NavItem({
  caseId,
  item,
  pathname,
  cloud,
}: {
  caseId: string;
  item: NavEntry;
  pathname: string;
  cloud: ReturnType<typeof caseCloud>;
}) {
  const label = item.panel ? panelLabel(cloud, item.panel) : (item.label ?? "");
  const Icon = item.icon;

  if (item.soon) {
    return (
      <span className="sb-nav-item sb-nav-item-soon" aria-disabled>
        <Icon className="shrink-0" strokeWidth={1.75} aria-hidden />
        {label}
      </span>
    );
  }

  const href = `/cases/${caseId}/${item.href}`;
  const active = pathname === href || pathname.startsWith(href + "/");

  return (
    <Link href={href} className={cn("sb-nav-item", active && "active")}>
      <Icon className="shrink-0" strokeWidth={1.75} aria-hidden />
      {label}
    </Link>
  );
}

export function CaseSidebar({ caseId }: { caseId: string }) {
  const pathname = usePathname();
  const { summary } = useCase();
  const cloud = caseCloud(summary?.cloud);

  return (
    <aside className="app-sidebar">
      <Link href={CASES_HREF} className="sb-brand">
        <div className="sb-brand-mark">
          <Shield className="h-[19px] w-[19px]" strokeWidth={1.8} aria-hidden />
        </div>
        <div className="sb-brand-title">Ventra</div>
      </Link>

      <BackToCases />

      <nav className="sb-nav">
        <div className="sb-nav-section">Investigate</div>
        {INVESTIGATE.filter((item) => item.href !== "cloudwatch" || cloud === "aws").map(
          (item) => (
          <NavItem
            key={item.href}
            caseId={caseId}
            item={item}
            pathname={pathname}
            cloud={cloud}
          />
        ),
        )}

        <div className="sb-nav-section">Package</div>
        {PACKAGE.map((item) => (
          <NavItem
            key={item.href}
            caseId={caseId}
            item={item}
            pathname={pathname}
            cloud={cloud}
          />
        ))}

      </nav>

      <div className="sb-footer">
        <div className="sb-readonly-pill">
          <span className="sb-readonly-dot" />
          READ-ONLY
        </div>
      </div>
    </aside>
  );
}
