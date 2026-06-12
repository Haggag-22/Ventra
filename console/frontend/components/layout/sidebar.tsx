"use client";

import { BackToCases } from "@/components/layout/back-to-cases";
import { CASES_HREF } from "@/lib/routes";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

type NavEntry = {
  href?: string;
  label: string;
  icon: ReactNode;
  soon?: boolean;
};

const INVESTIGATE: NavEntry[] = [
  {
    href: "overview",
    label: "Overview",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <rect x="3" y="3" width="7" height="9" rx="1.5" />
        <rect x="14" y="3" width="7" height="5" rx="1.5" />
        <rect x="14" y="12" width="7" height="9" rx="1.5" />
        <rect x="3" y="16" width="7" height="5" rx="1.5" />
      </svg>
    ),
  },
  {
    href: "cloudtrail",
    label: "CloudTrail Timeline",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3.5 2" />
      </svg>
    ),
  },
  {
    href: "search",
    label: "Security Findings",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <path d="M12 3l9 16H3l9-16z" />
        <path d="M12 10v4" />
        <path d="M12 17.5v.5" />
      </svg>
    ),
  },
  {
    href: "identity",
    label: "Identity & Access",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <circle cx="12" cy="8" r="4" />
        <path d="M4 21c0-4 3.5-6.5 8-6.5s8 2.5 8 6.5" />
      </svg>
    ),
  },
  {
    href: "network",
    label: "Network Activity",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <circle cx="5" cy="12" r="2.5" />
        <circle cx="19" cy="5" r="2.5" />
        <circle cx="19" cy="19" r="2.5" />
        <path d="M7.3 11l9.4-5M7.3 13l9.4 5" />
      </svg>
    ),
  },
];

const PACKAGE: NavEntry[] = [
  {
    href: "collection",
    label: "Logs Coverage",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <path d="M4 12l5 5L20 6" />
      </svg>
    ),
  },
  {
    href: "resources",
    label: "Resource Inventory",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
      </svg>
    ),
  },
  {
    label: "File Browser",
    soon: true,
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <path d="M4 4h6l2 3h8a1 1 0 011 1v11a1 1 0 01-1 1H4a1 1 0 01-1-1V5a1 1 0 011-1z" />
      </svg>
    ),
  },
];

function NavItem({
  caseId,
  item,
  pathname,
}: {
  caseId: string;
  item: NavEntry;
  pathname: string;
}) {
  if (item.soon || !item.href) {
    return (
      <span className="sb-nav-item sb-nav-item-soon" aria-disabled>
        {item.icon}
        {item.label}
      </span>
    );
  }

  const href = `/cases/${caseId}/${item.href}`;
  const active = pathname === href || pathname.startsWith(href + "/");

  return (
    <Link href={href} className={cn("sb-nav-item", active && "active")}>
      {item.icon}
      {item.label}
    </Link>
  );
}

export function Sidebar({ caseId }: { caseId: string }) {
  const pathname = usePathname();

  return (
    <aside className="app-sidebar">
      <Link href={CASES_HREF} className="sb-brand">
        <div className="sb-brand-mark">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden
          >
            <path d="M12 22s8-3.5 8-10V5l-8-3-8 3v7c0 6.5 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <div>
          <div className="sb-brand-title">Ventra</div>
          <div className="sb-brand-sub">Evidence Viewer</div>
        </div>
      </Link>

      <BackToCases />

      <nav className="sb-nav">
        <div className="sb-nav-section">Investigate</div>
        {INVESTIGATE.map((item) => (
          <NavItem key={item.label} caseId={caseId} item={item} pathname={pathname} />
        ))}

        <div className="sb-nav-section">Package</div>
        {PACKAGE.map((item) => (
          <NavItem key={item.label} caseId={caseId} item={item} pathname={pathname} />
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
