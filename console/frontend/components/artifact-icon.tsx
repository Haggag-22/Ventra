import { artifactIconSrc } from "@/lib/artifact-icons";
import { cn } from "@/lib/utils";
import Image from "next/image";

export function ArtifactIcon({
  cloud,
  collector,
  size = 28,
  className,
}: {
  cloud: string;
  collector: string;
  size?: number;
  className?: string;
}) {
  const src = artifactIconSrc(cloud, collector);
  if (!src) {
    return (
      <span
        className={cn(
          "inline-flex shrink-0 items-center justify-center rounded-md bg-surface-2 text-2xs font-medium uppercase text-fg-subtle",
          className,
        )}
        style={{ width: size, height: size }}
      >
        {collector.slice(0, 2)}
      </span>
    );
  }

  return (
    <span
      className={cn("inline-flex shrink-0 items-center justify-center overflow-hidden rounded-md", className)}
      style={{ width: size, height: size }}
    >
      <Image
        src={src}
        alt=""
        width={size}
        height={size}
        className="h-full w-full object-contain"
        unoptimized
      />
    </span>
  );
}
