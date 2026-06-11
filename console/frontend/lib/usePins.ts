"use client";

import { useCallback, useEffect, useState } from "react";

// Pinned evidence for the Report panel. Stored per-case in localStorage so an analyst's
// in-progress report survives reloads. (A server-backed report store is a later phase.)

export interface Pin {
  id: string;
  caseId: string;
  kind: "event" | "finding" | "chart" | "note";
  title: string;
  detail?: string;
  timestamp?: string;
  ref?: Record<string, unknown>;
  createdAt: number;
}

const KEY = (caseId: string) => `harbor.pins.${caseId}`;
const EVT = "harbor:pins";

function read(caseId: string): Pin[] {
  try {
    return JSON.parse(localStorage.getItem(KEY(caseId)) || "[]");
  } catch {
    return [];
  }
}

function write(caseId: string, pins: Pin[]) {
  localStorage.setItem(KEY(caseId), JSON.stringify(pins));
  window.dispatchEvent(new CustomEvent(EVT, { detail: caseId }));
}

export function usePins(caseId: string) {
  const [pins, setPins] = useState<Pin[]>([]);

  useEffect(() => {
    setPins(read(caseId));
    const onChange = (e: Event) => {
      if ((e as CustomEvent).detail === caseId) setPins(read(caseId));
    };
    window.addEventListener(EVT, onChange);
    return () => window.removeEventListener(EVT, onChange);
  }, [caseId]);

  const add = useCallback(
    (pin: Omit<Pin, "id" | "createdAt" | "caseId">) => {
      const existing = read(caseId);
      const id = `${pin.kind}-${pin.title}-${pin.timestamp ?? ""}`;
      if (existing.some((p) => p.id === id)) return;
      write(caseId, [...existing, { ...pin, id, caseId, createdAt: Date.now() }]);
    },
    [caseId],
  );

  const remove = useCallback(
    (id: string) => write(caseId, read(caseId).filter((p) => p.id !== id)),
    [caseId],
  );

  const has = useCallback(
    (id: string) => pins.some((p) => p.id === id),
    [pins],
  );

  return { pins, add, remove, has };
}
