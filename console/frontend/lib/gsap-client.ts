"use client";

import gsap from "gsap";
import { useGSAP } from "@gsap/react";

gsap.registerPlugin(useGSAP);

export { gsap, useGSAP };

/** Duration helper — returns 0 when user prefers reduced motion. */
export function motionDuration(base: number, reduceMotion: boolean): number {
  return reduceMotion ? 0 : base;
}

/** Safe read of matchMedia conditions from gsap.matchMedia callback context. */
export function matchMediaReduced(context: { conditions?: { reduceMotion?: boolean } }): boolean {
  return Boolean(context.conditions?.reduceMotion);
}
