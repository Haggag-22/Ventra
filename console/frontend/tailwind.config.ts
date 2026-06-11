import type { Config } from "tailwindcss";

/**
 * Harbor design tokens. Colors are CSS variables (see app/globals.css) so dark / light /
 * high-contrast themes swap without rebuilding. Severity and category palettes are stable
 * across every panel.
 */
const config: Config = {
  darkMode: ["class"],
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "rgb(var(--bg) / <alpha-value>)",
        raised: "rgb(var(--raised) / <alpha-value>)",
        surface: "rgb(var(--surface) / <alpha-value>)",
        "surface-2": "rgb(var(--surface-2) / <alpha-value>)",
        border: "rgb(var(--border) / <alpha-value>)",
        "border-strong": "rgb(var(--border-strong) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
        fg: "rgb(var(--fg) / <alpha-value>)",
        "fg-subtle": "rgb(var(--fg-subtle) / <alpha-value>)",
        "fg-faint": "rgb(var(--fg-faint) / <alpha-value>)",
        accent: "rgb(var(--accent) / <alpha-value>)",
        "accent-fg": "rgb(var(--accent-fg) / <alpha-value>)",
        // severity
        critical: "rgb(var(--sev-critical) / <alpha-value>)",
        high: "rgb(var(--sev-high) / <alpha-value>)",
        medium: "rgb(var(--sev-medium) / <alpha-value>)",
        low: "rgb(var(--sev-low) / <alpha-value>)",
        info: "rgb(var(--sev-info) / <alpha-value>)",
        // integrity
        "ok-green": "rgb(var(--ok-green) / <alpha-value>)",
        "warn-amber": "rgb(var(--warn-amber) / <alpha-value>)",
        "bad-red": "rgb(var(--bad-red) / <alpha-value>)",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      borderRadius: {
        lg: "0.625rem",
        md: "0.4375rem",
        sm: "0.3125rem",
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(0 0 0 / 0.25), 0 1px 1px -1px rgb(0 0 0 / 0.2)",
        pop: "0 12px 32px -8px rgb(0 0 0 / 0.55), 0 4px 8px -4px rgb(0 0 0 / 0.4)",
      },
      keyframes: {
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "slide-in": {
          from: { transform: "translateX(8px)", opacity: "0" },
          to: { transform: "translateX(0)", opacity: "1" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.15s ease-out",
        "slide-in": "slide-in 0.18s ease-out",
      },
    },
  },
  plugins: [],
};

export default config;
