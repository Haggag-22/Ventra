import { ACQUIRE_PLATFORM_LABELS, CASE_PLATFORM_LABELS, CLOUD_LABELS, type AcquirePlatform, type Cloud } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import { Container } from "lucide-react";
import Image from "next/image";

/** Shared size for all cloud provider logos across the console UI (24px). */
export const PROVIDER_ICON_SIZE = 24;

const LOGOS: Record<Cloud | "m365", { src: string; alt: string }> = {
  aws: { src: "/logos/aws.png", alt: "Amazon Web Services" },
  azure: { src: "/logos/azure.png", alt: "Microsoft Azure" },
  gcp: { src: "/logos/gcp.png", alt: "Google Cloud" },
  m365: { src: "/icons/icon8/m365.png", alt: "Microsoft 365" },
};

export function CloudProviderIcon({
  cloud,
  className,
  variant = "icon",
}: {
  cloud: string;
  className?: string;
  variant?: "icon" | "badge";
}) {
  const key = cloud.toLowerCase();
  if (key === "kubernetes") {
    return (
      <span
        className={cn("inline-flex shrink-0 items-center justify-center text-accent", className)}
        style={{ width: PROVIDER_ICON_SIZE, height: PROVIDER_ICON_SIZE }}
        title="Kubernetes"
      >
        <Container className="h-full w-full" strokeWidth={1.75} />
      </span>
    );
  }

  const meta = LOGOS[key as Cloud | "m365"];

  if (!meta) {
    return (
      <span
        className={cn(
          "inline-flex items-center justify-center rounded bg-surface-2 text-2xs font-medium uppercase text-fg-subtle",
          className,
        )}
        style={{ width: PROVIDER_ICON_SIZE, height: PROVIDER_ICON_SIZE }}
      >
        {cloud.slice(0, 2)}
      </span>
    );
  }

  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center justify-center",
        variant === "badge" && "overflow-hidden rounded-md",
        className,
      )}
      style={{ width: PROVIDER_ICON_SIZE, height: PROVIDER_ICON_SIZE }}
      title={meta.alt}
    >
      <Image
        src={meta.src}
        alt={meta.alt}
        width={PROVIDER_ICON_SIZE}
        height={PROVIDER_ICON_SIZE}
        className="max-h-full max-w-full object-contain"
      />
    </span>
  );
}

export function CloudPlatformLabel({
  cloud,
  className,
}: {
  cloud: string;
  className?: string;
}) {
  const key = cloud.toLowerCase();
  const label =
    CASE_PLATFORM_LABELS[key as keyof typeof CASE_PLATFORM_LABELS]
    ?? ACQUIRE_PLATFORM_LABELS[key as AcquirePlatform]
    ?? CLOUD_LABELS[key as Cloud]
    ?? cloud.toUpperCase();

  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <CloudProviderIcon cloud={cloud} />
      <span className="text-fg">{label}</span>
    </span>
  );
}
