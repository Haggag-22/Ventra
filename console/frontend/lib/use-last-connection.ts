"use client";

import { useSyncExternalStore } from "react";
import { readLastConnection } from "./provider-storage";

function subscribe(onChange: () => void): () => void {
  window.addEventListener("storage", onChange);
  return () => window.removeEventListener("storage", onChange);
}

/**
 * The last-used connection for rendering. Empty during hydration (the server and the static
 * export have no localStorage), so markup built from it matches the pre-rendered HTML.
 */
export function useLastConnection(): string {
  return useSyncExternalStore(subscribe, readLastConnection, () => "");
}
