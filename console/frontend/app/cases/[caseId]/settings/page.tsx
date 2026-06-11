"use client";

import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Card, CardHeader } from "@/components/ui";
import { useUI } from "@/app/providers";
import { api } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { Eye, Lock, Monitor, Settings, ShieldOff } from "lucide-react";

const ROLES = [
  { role: "Responder", can: "Acquire evidence (run the collector)" },
  { role: "Investigator", can: "Analyze, import cases, export reports" },
  { role: "Data Custodian", can: "Manage evidence lifecycle, delete cases, view audit" },
  { role: "Analyst", can: "Read-only analysis and reporting" },
];

export default function SettingsPage() {
  const { caseId } = useCase();
  const { theme, setTheme, density, setDensity } = useUI();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });

  return (
    <>
      <PanelHeader icon={Settings} title="Settings" description="Appearance, access, and backend" />
      <PanelBody className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Appearance */}
        <Card>
          <CardHeader title="Appearance" icon={Monitor} />
          <div className="space-y-4 p-4">
            <div>
              <div className="stat-label mb-2">Theme</div>
              <div className="flex gap-2">
                {(["dark", "light", "contrast"] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTheme(t)}
                    className={`rounded-md border px-3 py-1.5 text-xs capitalize ${
                      theme === t ? "border-accent/40 bg-accent/12 text-accent" : "border-border text-fg-subtle hover:text-fg"
                    }`}
                  >
                    {t === "contrast" ? "High contrast" : t}
                  </button>
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
                      density === d ? "border-accent/40 bg-accent/12 text-accent" : "border-border text-fg-subtle hover:text-fg"
                    }`}
                  >
                    {d}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </Card>

        {/* Roles */}
        <Card>
          <CardHeader title="Roles & access" subtitle={`You are: ${me.data?.role ?? "investigator"}`} icon={Lock} />
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

        {/* Backend */}
        <Card>
          <CardHeader title="Backend" icon={Eye} />
          <div className="space-y-2 p-4 text-sm">
            <Row k="Status" v={health.data?.status ?? "—"} />
            <Row k="Version" v={health.data?.version ?? "—"} />
            <Row k="Case store" v={<span className="mono text-2xs">{(health.data as any)?.case_store ?? "—"}</span>} />
            <Row k="Active case" v={<span className="mono">{caseId}</span>} />
          </div>
        </Card>

        {/* Privacy */}
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
      </PanelBody>
    </>
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
