"use client";

import { CASES_HREF } from "@/lib/routes";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";

export function BackToCases() {
  return (
    <div className="sb-back-wrap">
      <Link href={CASES_HREF} className="sb-back-btn">
        <ArrowLeft className="sb-back-icon" strokeWidth={2.2} aria-hidden />
        <span>Back to cases</span>
      </Link>
    </div>
  );
}
