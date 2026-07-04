import type { Config } from "tailwindcss";

/**
 * Ventra design tokens. Colors are CSS variables (see app/globals.css) so dark / light /
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
        sidebar: "rgb(var(--sidebar) / <alpha-value>)",
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
        "accent-cta": "rgb(var(--accent-cta) / <alpha-value>)",
        "accent-cta-fg": "rgb(var(--accent-cta-fg) / <alpha-value>)",
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
        lg: "0.75rem",
        md: "0.5rem",
        sm: "0.375rem",
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(0 0 0 / 0.3), inset 0 1px 0 0 rgb(255 255 255 / 0.025)",
        pop: "0 16px 40px -12px rgb(0 0 0 / 0.6), 0 4px 10px -4px rgb(0 0 0 / 0.45)",
        glow: "0 0 0 1px rgb(91 155 255 / 0.35), 0 6px 22px -6px rgb(91 155 255 / 0.4)",
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
