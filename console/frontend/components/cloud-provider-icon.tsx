import { CASE_PLATFORM_LABELS, CLOUD_LABELS, type Cloud } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import { Container } from "lucide-react";
import Image from "next/image";

const LOGOS: Record<Cloud, { src: string; alt: string; aspect: number }> = {
  aws: { src: "/logos/aws.png", alt: "Amazon Web Services", aspect: 662 / 464 },
  azure: { src: "/logos/azure.png", alt: "Microsoft Azure", aspect: 1 },
  gcp: { src: "/logos/gcp.png", alt: "Google Cloud", aspect: 1 },
};

export function CloudProviderIcon({
  cloud,
  className,
  size = 20,
  variant = "icon",
}: {
  cloud: string;
  className?: string;
  size?: number;
  variant?: "icon" | "badge";
}) {
  const key = cloud.toLowerCase();
  if (key === "kubernetes") {
    return (
      <span
        className={cn("inline-flex shrink-0 items-center justify-center text-accent", className)}
        style={{ width: size, height: size }}
        title="Kubernetes"
      >
        <Container className="h-full w-full" strokeWidth={1.75} />
      </span>
    );
  }

  const meta = LOGOS[key as Cloud];

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

  const height = size;
  const width = Math.round(size * meta.aspect);

  const img = (
    <Image
      src={meta.src}
      alt={meta.alt}
      width={width}
      height={height}
      className="h-full w-full object-contain"
    />
  );

  if (variant === "badge") {
    return (
      <span
        className={cn(
          "inline-flex shrink-0 items-center justify-center overflow-hidden rounded-md",
          className,
        )}
        style={{ width, height }}
        title={meta.alt}
      >
        {img}
      </span>
    );
  }

  return (
    <span
      className={cn("inline-flex shrink-0 items-center justify-center", className)}
      style={{ width, height }}
      title={meta.alt}
    >
      {img}
    </span>
  );
}

export function CloudPlatformLabel({
  cloud,
  className,
  size = 18,
}: {
  cloud: string;
  className?: string;
  size?: number;
}) {
  const key = cloud.toLowerCase();
  const label =
    CASE_PLATFORM_LABELS[key as keyof typeof CASE_PLATFORM_LABELS]
    ?? CLOUD_LABELS[key as Cloud]
    ?? cloud.toUpperCase();

  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <CloudProviderIcon cloud={cloud} size={size} />
      <span className="text-fg">{label}</span>
    </span>
  );
}
