"use client";

import type { DeploymentTemplate } from "@/lib/deployment-templates";
import { cn } from "@/lib/utils";
import { Cloud, Download, FileCode2, FileJson } from "lucide-react";

function templateIcon(kind: DeploymentTemplate["kind"]) {
  switch (kind) {
    case "cloudformation":
      return Cloud;
    case "terraform":
      return FileCode2;
    default:
      return FileJson;
  }
}

export function DeploymentTemplateLinks({
  templates,
  title = "Deploy with infrastructure as code",
  description,
  className,
  compact = false,
}: {
  templates: DeploymentTemplate[];
  title?: string;
  description?: string;
  className?: string;
  compact?: boolean;
}) {
  if (!templates.length) return null;

  const iac = templates.filter((t) => t.kind === "cloudformation" || t.kind === "terraform");
  const policies = templates.filter((t) => t.kind === "policy" || t.kind === "arm");

  return (
    <div className={cn("rounded-lg border border-border bg-surface-2/40 p-4", className)}>
      <p className="text-sm font-medium text-fg">{title}</p>
      {description ? (
        <p className="mt-1 text-xs leading-relaxed text-fg-subtle">{description}</p>
      ) : null}

      {iac.length > 0 && (
        <div className={cn("mt-4", !compact && "relative")}>
          {!compact && (
            <div className="absolute inset-x-0 top-0 flex items-center" aria-hidden>
              <div className="w-full border-t border-border" />
            </div>
          )}
          {!compact && (
            <div className="relative flex justify-center">
              <span className="bg-surface-2/40 px-2 text-2xs uppercase tracking-wide text-fg-faint">
                or
              </span>
            </div>
          )}
          <ul className={cn("flex flex-wrap gap-2", !compact && "mt-3")}>
            {iac.map((template) => {
              const Icon = templateIcon(template.kind);
              return (
                <li key={template.id}>
                  <a
                    href={template.href}
                    download={template.filename}
                    className="inline-flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-2 text-xs font-medium text-fg transition-colors hover:border-ok-green/40 hover:bg-ok-green/5 hover:text-ok-green"
                  >
                    <Icon className="h-4 w-4 shrink-0" aria-hidden />
                    <span>{template.label}</span>
                    <Download className="h-3 w-3 opacity-60" aria-hidden />
                  </a>
                </li>
              );
            })}
          </ul>
          {iac.some((t) => t.description) && (
            <ul className="mt-2 space-y-1">
              {iac
                .filter((t) => t.description)
                .map((t) => (
                  <li key={t.id} className="text-2xs text-fg-faint">
                    {t.label}: {t.description}
                  </li>
                ))}
            </ul>
          )}
        </div>
      )}

      {policies.length > 0 && (
        <div className={cn(iac.length > 0 && "mt-4 border-t border-border pt-4")}>
          <p className="text-2xs font-semibold uppercase tracking-wide text-fg-faint">
            Policy references
          </p>
          <ul className="mt-2 flex flex-wrap gap-2">
            {policies.map((template) => (
              <li key={template.id}>
                <a
                  href={template.href}
                  download={template.filename}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-fg-subtle transition-colors hover:border-border-strong hover:text-fg"
                >
                  <FileJson className="h-3.5 w-3.5" aria-hidden />
                  {template.label}
                  <Download className="h-3 w-3 opacity-50" aria-hidden />
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
