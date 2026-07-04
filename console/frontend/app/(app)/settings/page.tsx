"use client";

import { Card, CardHeader } from "@/components/ui";
import { api } from "@/lib/api";
import { useUI } from "@/app/providers";
import { DARK_THEMES, OTHER_THEMES } from "@/lib/themes";
import { useQuery } from "@tanstack/react-query";
import { Eye, Lock, Monitor, Settings, ShieldOff } from "lucide-react";

const ROLES = [
  { role: "Responder", can: "Acquire evidence (run the collector)" },
  { role: "Investigator", can: "Analyze, import cases, export reports" },
  { role: "Data Custodian", can: "Manage evidence lifecycle, delete cases, view audit" },
  { role: "Analyst", can: "Read-only analysis and reporting" },
];

export default function SettingsPage() {
  const { theme, setTheme, density, setDensity } = useUI();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });

  return (
    <div className="px-6 py-8">
      <div className="mb-6">
        <h1 className="page-title">
          <Settings className="h-5 w-5 text-accent" />
          Settings
        </h1>
        <p className="page-subtitle">Appearance, access, and backend health.</p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Appearance" icon={Monitor} />
          <div className="space-y-5 p-4">
            <div>
              <div className="stat-label mb-2">Dark themes</div>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {DARK_THEMES.map((t) => (
                  <ThemeSwatch
                    key={t.id}
                    name={t.name}
                    bg={t.bg}
                    accent={t.accent}
                    active={theme === t.id}
                    onSelect={() => setTheme(t.id)}
                  />
                ))}
              </div>
            </div>
            <div>
              <div className="stat-label mb-2">Other themes</div>
              <div className="flex flex-wrap gap-2">
                {OTHER_THEMES.map((t) => (
                  <ThemeSwatch
                    key={t.id}
                    name={t.name}
                    bg={t.bg}
                    accent={t.accent}
                    active={theme === t.id}
                    onSelect={() => setTheme(t.id)}
                    compact
                  />
                ))}
              </div>
            </div>
            <div>
              <div className="stat-label mb-2">Density</div>
              <div className="flex gap-2">
                {(["comfortable", "compact"] as const).map((d) => (
                  <button
                    key={d}
                    onClick={() => setDensity(d)}
                    className={`rounded-md border px-3 py-1.5 text-xs capitalize ${
                      density === d
                        ? "border-accent/40 bg-accent/12 text-accent"
                        : "border-border text-fg-subtle hover:text-fg"
                    }`}
                  >
                    {d}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Roles & access"
            subtitle={`You are: ${me.data?.role ?? "investigator"}`}
            icon={Lock}
          />
          <div className="divide-y divide-border">
            {ROLES.map((r) => (
              <div key={r.role} className="flex items-start justify-between gap-4 px-4 py-2.5">
                <span className="text-sm font-medium text-fg">{r.role}</span>
                <span className="text-right text-xs text-fg-subtle">{r.can}</span>
              </div>
            ))}
          </div>
          <div className="border-t border-border px-4 py-3 text-2xs text-fg-subtle">
            Separation of duties mirrors AWS forensic guidance. RBAC is enforced server-side.
          </div>
        </Card>

        <Card>
          <CardHeader title="Backend" icon={Eye} />
          <div className="space-y-2 p-4 text-sm">
            <Row k="Status" v={health.data?.status ?? "—"} />
            <Row k="Version" v={health.data?.version ?? "—"} />
            <Row
              k="Case store"
              v={<span className="mono text-2xs">{(health.data as { case_store?: string })?.case_store ?? "—"}</span>}
            />
          </div>
        </Card>

        <Card>
          <CardHeader title="Privacy" icon={ShieldOff} />
          <div className="space-y-3 p-4 text-sm text-fg-subtle">
            <div className="flex items-center gap-2 text-ok-green">
              <ShieldOff className="h-4 w-4" />
              <span className="font-medium">Telemetry is off and cannot be enabled.</span>
            </div>
            <p className="leading-relaxed">
              The console makes no outbound calls. All assets are served locally; there are no
              analytics, no CDN fonts, and no map tiles fetched at runtime. Evidence never leaves
              this machine.
            </p>
          </div>
        </Card>
      </div>
    </div>
  );
}

function ThemeSwatch({
  name,
  bg,
  accent,
  active,
  onSelect,
  compact = false,
}: {
  name: string;
  bg: string;
  accent: string;
  active: boolean;
  onSelect: () => void;
  compact?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`rounded-lg border p-2 text-left transition-colors ${
        compact ? "min-w-[9rem]" : "w-full"
      } ${
        active
          ? "border-accent/50 bg-accent/8 ring-1 ring-accent/30"
          : "border-border hover:border-border-strong hover:bg-surface-2"
      }`}
      aria-pressed={active}
      aria-label={`${name} theme`}
    >
      <div
        className="h-9 overflow-hidden rounded-md border border-border/40"
        style={{
          background: `linear-gradient(135deg, rgb(${bg}) 58%, rgb(${accent}) 58%)`,
        }}
        aria-hidden
      />
      <span className={`mt-1.5 block truncate ${compact ? "text-xs" : "text-2xs"} text-fg-subtle`}>
        {name}
      </span>
    </button>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-fg-subtle">{k}</span>
      <span className="text-fg">{v}</span>
    </div>
  );
}
