"use client";

import { AuthGate } from "@/components/auth-gate";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import {
  THEME_CLASS_NAMES,
  type Theme,
  isValidTheme,
} from "@/lib/themes";

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
  theme: Theme;
  setTheme: (t: Theme) => void;
  density: Density;
  setDensity: (d: Density) => void;
}

const UIContext = createContext<UIState | null>(null);

export function useUI(): UIState {
  const ctx = useContext(UIContext);
  if (!ctx) throw new Error("useUI must be used within Providers");
  return ctx;
}

export type { Theme };

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(makeClient);
  const [theme, setThemeState] = useState<Theme>("dark");
  const [density, setDensityState] = useState<Density>("comfortable");

  useEffect(() => {
    const stored = localStorage.getItem("ventra.theme");
    const t: Theme = isValidTheme(stored) ? stored : "dark";
    const d = (localStorage.getItem("ventra.density") as Density) || "comfortable";
    setThemeState(t);
    setDensityState(d);
  }, []);

  useEffect(() => {
    const el = document.documentElement;
    el.classList.remove(...THEME_CLASS_NAMES);
    el.classList.add(`theme-${theme}`);
    el.dataset.density = density;
  }, [theme, density]);

  const setTheme = (t: Theme) => {
    setThemeState(t);
    localStorage.setItem("ventra.theme", t);
  };
  const setDensity = (d: Density) => {
    setDensityState(d);
    localStorage.setItem("ventra.density", d);
  };

  const ui = useMemo(
    () => ({ theme, setTheme, density, setDensity }),
    [theme, density],
  );

  return (
    <QueryClientProvider client={client}>
      <UIContext.Provider value={ui}>
        {children}
        <AuthGate />
      </UIContext.Provider>
    </QueryClientProvider>
  );
}
