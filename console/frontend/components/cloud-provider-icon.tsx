import { ACQUIRE_PLATFORM_LABELS, CASE_PLATFORM_LABELS, CLOUD_LABELS, type Cloud } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import Image from "next/image";

/** Shared size for all cloud provider logos across the console UI (24px). */
export const PROVIDER_ICON_SIZE = 24;

const LOGOS: Record<Cloud | "m365", { src: string; alt: string }> = {
  aws: { src: "/logos/aws.png", alt: "Amazon Web Services" },
  azure: { src: "/logos/azure.png", alt: "Microsoft Azure" },
  gcp: { src: "/logos/gcp.png", alt: "Google Cloud" },
  kubernetes: { src: "/logos/kubernetes.svg", alt: "Kubernetes" },
  m365: { src: "/logos/m365.png", alt: "M365" },
};

export function CloudProviderIcon({
  cloud,
  className,
  variant = "icon",
  size = PROVIDER_ICON_SIZE,
}: {
  cloud: string;
  className?: string;
  variant?: "icon" | "badge";
  /** Pixel size for the logo (defaults to PROVIDER_ICON_SIZE). */
  size?: number;
}) {
  const key = cloud.toLowerCase();
  const meta = LOGOS[key as Cloud | "m365"];

  if (!meta) {
    return (
      <span
        className={cn(
          "inline-flex items-center justify-center rounded bg-surface-2 text-2xs font-medium uppercase text-fg-subtle",
          className,
        )}
        style={{ width: size, height: size }}
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
      style={{ width: size, height: size }}
      title={meta.alt}
    >
      <Image
        src={meta.src}
        alt={meta.alt}
        width={size}
        height={size}
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
    ?? ACQUIRE_PLATFORM_LABELS[key as keyof typeof ACQUIRE_PLATFORM_LABELS]
    ?? CLOUD_LABELS[key as Cloud]
    ?? (key === "kubernetes" ? "Kubernetes" : cloud.toUpperCase());

  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <CloudProviderIcon cloud={cloud} />
      <span className="font-semibold text-fg">{label}</span>
    </span>
  );
}
