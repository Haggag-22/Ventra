"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, useState } from "react";

// ---- React Query -----------------------------------------------------------------------

function makeClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { staleTime: 30_000, refetchOnWindowFocus: false, retry: 1 },
    },
  });
}

// ---- Theme -----------------------------------------------------------------------------

type Theme = "dark" | "light" | "contrast";
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

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(makeClient);
  const [theme, setThemeState] = useState<Theme>("dark");
  const [density, setDensityState] = useState<Density>("comfortable");

  useEffect(() => {
    const t = (localStorage.getItem("harbor.theme") as Theme) || "dark";
    const d = (localStorage.getItem("harbor.density") as Density) || "comfortable";
    setThemeState(t);
    setDensityState(d);
  }, []);

  useEffect(() => {
    const el = document.documentElement;
    el.classList.remove("theme-dark", "theme-light", "theme-contrast");
    el.classList.add(`theme-${theme}`);
    el.dataset.density = density;
  }, [theme, density]);

  const setTheme = (t: Theme) => {
    setThemeState(t);
    localStorage.setItem("harbor.theme", t);
  };
  const setDensity = (d: Density) => {
    setDensityState(d);
    localStorage.setItem("harbor.density", d);
  };

  const ui = useMemo(
    () => ({ theme, setTheme, density, setDensity }),
    [theme, density],
  );

  return (
    <QueryClientProvider client={client}>
      <UIContext.Provider value={ui}>{children}</UIContext.Provider>
    </QueryClientProvider>
  );
}
