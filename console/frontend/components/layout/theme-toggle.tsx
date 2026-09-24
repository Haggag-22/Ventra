"use client";

import { useUI } from "@/app/providers";
import { Moon, Sun, SunMoon } from "lucide-react";

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, setTheme } = useUI();
  const cycle = () => {
    const next =
      theme === "light" ? "contrast" : theme === "contrast" ? "dark" : "light";
    setTheme(next);
  };
  const Icon = theme === "light" ? Sun : theme === "contrast" ? SunMoon : Moon;
  return (
    <button
      type="button"
      onClick={cycle}
      className={
        className ??
        "inline-flex h-8 w-8 items-center justify-center rounded-md border border-border bg-surface text-fg-subtle transition-colors hover:border-accent/40 hover:bg-surface-2 hover:text-fg"
      }
      title={`Theme: ${theme}`}
      aria-label={`Switch theme (current: ${theme})`}
    >
      <Icon className="h-4 w-4" />
    </button>
  );
}
