"use client";

import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { usePathname } from "next/navigation";
import { useRef, type ReactNode } from "react";

/** Light fade-in on route change — dashboard pages only. */
export function PageTransition({ children }: { children: ReactNode }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const pathname = usePathname();

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(
        {
          reduceMotion: "(prefers-reduced-motion: reduce)",
          motion: "(prefers-reduced-motion: no-preference)",
        },
        (context) => {
          const reduceMotion = matchMediaReduced(context);
          gsap.from(containerRef.current, {
            autoAlpha: reduceMotion ? 1 : 0,
            duration: reduceMotion ? 0 : 0.2,
            ease: "power1.out",
          });
        },
        containerRef,
      );
      return () => mm.revert();
    },
    { scope: containerRef, dependencies: [pathname], revertOnUpdate: true },
  );

  return (
    <div ref={containerRef} className="min-h-0 flex-1">
      {children}
    </div>
  );
}
