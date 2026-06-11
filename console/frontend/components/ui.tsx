"use client";

import { cn } from "@/lib/utils";
import { Loader2, type LucideIcon } from "lucide-react";
import React from "react";

// ---- Button ----------------------------------------------------------------------------

type ButtonVariant = "primary" | "primary-dark" | "secondary" | "ghost" | "danger" | "subtle";
type ButtonSize = "sm" | "md" | "icon";

const BTN_VARIANTS: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent/90 font-medium",
  "primary-dark": "bg-[rgb(30,58,138)] text-white hover:bg-[rgb(30,64,175)] font-medium shadow-sm",
  secondary: "bg-surface-2 text-fg border border-border hover:bg-surface-2/70",
  ghost: "text-fg-subtle hover:text-fg hover:bg-surface-2",
  danger: "bg-bad-red/15 text-bad-red border border-bad-red/30 hover:bg-bad-red/25",
  subtle: "text-fg-subtle hover:text-fg",
};
const BTN_SIZES: Record<ButtonSize, string> = {
  sm: "h-7 px-2.5 text-xs gap-1.5",
  md: "h-9 px-3.5 text-sm gap-2",
  icon: "h-8 w-8 justify-center",
};

export const Button = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: ButtonVariant;
    size?: ButtonSize;
    icon?: LucideIcon;
    loading?: boolean;
  }
>(function Button(
  { className, variant = "secondary", size = "md", icon: Icon, loading, children, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center rounded-md transition-colors disabled:opacity-50 disabled:pointer-events-none whitespace-nowrap",
        BTN_VARIANTS[variant],
        BTN_SIZES[size],
        className,
      )}
      {...props}
    >
      {loading ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : (
        Icon && <Icon className={cn(size === "icon" ? "h-4 w-4" : "h-3.5 w-3.5")} />
      )}
      {children}
    </button>
  );
});

// ---- Card ------------------------------------------------------------------------------

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("card", className)} {...props} />;
}

export function CardHeader({
  title,
  subtitle,
  icon: Icon,
  action,
  className,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: LucideIcon;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-3 px-4 py-3 border-b border-border", className)}>
      <div className="flex items-center gap-2.5 min-w-0">
        {Icon && <Icon className="h-4 w-4 text-fg-subtle shrink-0" />}
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-fg truncate">{title}</h3>
          {subtitle && <p className="text-xs text-fg-subtle mt-0.5 truncate">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}

// ---- Badge -----------------------------------------------------------------------------

export function Badge({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-2xs font-medium",
        className,
      )}
      {...props}
    >
      {children}
    </span>
  );
}

// ---- Input -----------------------------------------------------------------------------

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...props }, ref) {
    return (
      <input
        ref={ref}
        className={cn(
          "h-9 w-full rounded-md border border-border bg-surface px-3 text-sm text-fg",
          "placeholder:text-fg-subtle/70 focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/40",
          className,
        )}
        {...props}
      />
    );
  },
);

// ---- Spinner / Loading -----------------------------------------------------------------

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("h-4 w-4 animate-spin text-fg-subtle", className)} />;
}

export function LoadingPanel({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-fg-subtle">
      <Spinner className="h-5 w-5" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

// ---- Empty state -----------------------------------------------------------------------

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div className="rounded-xl border border-border bg-surface-2 p-3">
        <Icon className="h-6 w-6 text-fg-subtle" />
      </div>
      <div className="max-w-md">
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        {description && <p className="mt-1 text-sm text-fg-subtle leading-relaxed">{description}</p>}
      </div>
      {action}
    </div>
  );
}

// ---- Skeleton --------------------------------------------------------------------------

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-surface-2", className)} />;
}

// ---- Tooltip (CSS, no dependency) ------------------------------------------------------

export function Tooltip({
  content,
  children,
  side = "top",
}: {
  content: React.ReactNode;
  children: React.ReactNode;
  side?: "top" | "bottom";
}) {
  return (
    <span className="group/tt relative inline-flex">
      {children}
      <span
        role="tooltip"
        className={cn(
          "pointer-events-none absolute left-1/2 z-50 -translate-x-1/2 whitespace-nowrap rounded-md border border-border bg-surface-2 px-2 py-1 text-2xs text-fg opacity-0 shadow-pop transition-opacity group-hover/tt:opacity-100",
          side === "top" ? "bottom-full mb-1.5" : "top-full mt-1.5",
        )}
      >
        {content}
      </span>
    </span>
  );
}

// ---- Section heading -------------------------------------------------------------------

export function SectionTitle({ children, right }: { children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <h2 className="text-sm font-semibold text-fg">{children}</h2>
      {right}
    </div>
  );
}
