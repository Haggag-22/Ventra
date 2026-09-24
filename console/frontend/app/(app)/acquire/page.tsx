"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** Legacy bookmark — kit builder lives under Configuration → Acquire. */
export default function AcquireRedirectPage() {
  const router = useRouter();
  useEffect(() => {
    const q = typeof window !== "undefined" ? window.location.search : "";
    router.replace(q ? `/config/acquire${q}` : "/config/acquire");
  }, [router]);
  return null;
}
