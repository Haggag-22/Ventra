"use client";

import { gsap } from "@/lib/gsap-client";
import { useEffect, useState } from "react";

/** Tracks `(prefers-reduced-motion: reduce)` via gsap.matchMedia. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const mm = gsap.matchMedia();
    mm.add("(prefers-reduced-motion: reduce)", () => {
      setReduced(true);
    });
    mm.add("(prefers-reduced-motion: no-preference)", () => {
      setReduced(false);
    });
    return () => mm.revert();
  }, []);

  return reduced;
}
