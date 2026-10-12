"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { THEME_CLASS_NAMES } from "@/lib/themes";

// ---- React Query -----------------------------------------------------------------------

function makeClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { staleTime: 30_000, refetchOnWindowFocus: false, retry: 1 },
    },
  });
}

// ---- Theme -----------------------------------------------------------------------------

type Density = "comfortable" | "compact";

interface UIState {
  density: Density;
  setDensity: (d: Density) => void;
}

const UIContext = createContext<UIState | null>(null);

export function useUI(): UIState {
  const ctx = useContext(UIContext);
  if (!ctx) throw new Error("useUI must be used within Providers");
  return ctx;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(makeClient);
  const [density, setDensityState] = useState<Density>("comfortable");

  useEffect(() => {
    const d = (localStorage.getItem("ventra.density") as Density) || "comfortable";
    setDensityState(d);
    localStorage.removeItem("ventra.theme");
  }, []);

  useEffect(() => {
    const el = document.documentElement;
    el.classList.remove(...THEME_CLASS_NAMES);
    el.classList.add("theme-dark");
    el.dataset.density = density;
  }, [density]);

  const setDensity = (d: Density) => {
    setDensityState(d);
    localStorage.setItem("ventra.density", d);
  };

  const ui = useMemo(() => ({ density, setDensity }), [density]);

  return (
    <QueryClientProvider client={client}>
      <UIContext.Provider value={ui}>{children}</UIContext.Provider>
    </QueryClientProvider>
  );
}
