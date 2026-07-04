export const DARK_THEMES = [
  { id: "dark", name: "Ventra Dark", bg: "16 20 28", accent: "91 155 255" },
  { id: "dark-green", name: "Prowler Green", bg: "12 20 16", accent: "74 222 128" },
  { id: "dark-brown", name: "Warm Amber", bg: "22 17 14", accent: "251 191 36" },
  { id: "dark-slate", name: "Cool Slate", bg: "17 21 28", accent: "100 149 237" },
  { id: "dark-purple", name: "Soft Purple", bg: "20 16 28", accent: "167 139 250" },
  { id: "dark-teal", name: "Ocean Teal", bg: "12 22 26", accent: "45 212 191" },
  { id: "dark-forest", name: "Deep Forest", bg: "10 18 12", accent: "34 197 94" },
  { id: "dark-charcoal", name: "Charcoal", bg: "18 18 18", accent: "212 175 120" },
] as const;

export const OTHER_THEMES = [
  { id: "light", name: "Light", bg: "247 249 251", accent: "13 148 136" },
  { id: "contrast", name: "High contrast", bg: "0 0 0", accent: "56 248 220" },
] as const;

export const THEMES = [...DARK_THEMES, ...OTHER_THEMES] as const;

export type Theme = (typeof THEMES)[number]["id"];

export const THEME_CLASS_NAMES = THEMES.map((t) => `theme-${t.id}`);

const DARK_THEME_IDS = new Set<string>(DARK_THEMES.map((t) => t.id));

export function isDarkTheme(theme: Theme): boolean {
  return DARK_THEME_IDS.has(theme);
}

export function isValidTheme(value: string | null): value is Theme {
  return THEMES.some((t) => t.id === value);
}
