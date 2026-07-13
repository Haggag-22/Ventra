/** GCP log collection backend — mirrors acquisition.yaml ``gcp_log_backend``. */

export type GcpLogBackendMode = "logging_api" | "gcs";

export type GcpLogBackendConfig = {
  mode: GcpLogBackendMode;
  gcs?: {
    bucket?: string;
    prefix?: string;
  };
};

/** Collectors that read log rows (Cloud Logging API or GCS archive). */
export const GCP_LOGGING_COLLECTOR_IDS = new Set([
  "cloud_audit_admin",
  "cloud_audit_system",
  "cloud_audit_data",
  "login_events",
  "vpc_flow",
  "firewall_logs",
  "cloud_nat",
  "load_balancer",
  "cloud_cdn",
  "api_gateway",
  "cloud_dns",
  "vm_logs",
  "cloud_functions",
  "storage_access",
  "bigquery_audit",
  "cloud_sql",
  "secret_manager",
  "cloud_monitoring",
  "cloud_armor",
  "gke_audit",
]);

export function cartNeedsGcpLogBackend(collectors: string[]): boolean {
  return collectors.some((c) => GCP_LOGGING_COLLECTOR_IDS.has(c));
}

export type GcpLogBackendFormState = {
  mode: GcpLogBackendMode | "";
  gcsBucket: string;
  gcsPrefix: string;
};

export const DEFAULT_GCP_LOG_BACKEND_FORM: GcpLogBackendFormState = {
  mode: "",
  gcsBucket: "",
  gcsPrefix: "",
};

export function gcpConfigToForm(cfg?: GcpLogBackendConfig | null): GcpLogBackendFormState {
  if (!cfg?.mode) return { ...DEFAULT_GCP_LOG_BACKEND_FORM };
  const rawMode = (cfg as { mode?: string }).mode;
  const mode: GcpLogBackendFormState["mode"] =
    rawMode === "bigquery" ? "" : rawMode === "gcs" || rawMode === "logging_api" ? rawMode : "";
  return {
    mode,
    gcsBucket: cfg.gcs?.bucket ?? "",
    gcsPrefix: cfg.gcs?.prefix ?? "",
  };
}

export const GCP_LOG_BACKEND_DEFAULT_KEY = "ventra.gcp-log-default";

export function serializeGcpLogBackend(form: GcpLogBackendFormState): GcpLogBackendConfig | undefined {
  if (!form.mode) return undefined;
  if (form.mode === "logging_api") {
    return { mode: "logging_api" };
  }
  return {
    mode: "gcs",
    gcs: {
      bucket: form.gcsBucket.trim(),
      ...(form.gcsPrefix.trim() ? { prefix: form.gcsPrefix.trim() } : {}),
    },
  };
}

/** Returns an error message when the form is incomplete; null when valid. */
export function validateGcpLogBackendForm(
  form: GcpLogBackendFormState,
  needsStrategy: boolean,
): string | null {
  if (!needsStrategy) return null;
  if (!form.mode) {
    return "Choose how GCP logs should be collected before downloading the kit.";
  }
  if (form.mode === "gcs" && !form.gcsBucket.trim()) {
    return "Enter a GCS bucket.";
  }
  return null;
}

export const GCP_LOG_BACKEND_IAM: Record<GcpLogBackendMode, readonly string[]> = {
  logging_api: ["logging.logEntries.list"],
  gcs: ["storage.buckets.get", "storage.objects.get", "storage.objects.list"],
};

/** GCP yellow button style for all strategy actions. */
export const GCP_LOG_BACKEND_BUTTON_CLASS =
  "border-[#FBBC04]/45 bg-[#FBBC04]/12 text-[#FDD663] hover:bg-[#FBBC04]/22 hover:border-[#FBBC04]/60";

export const GCP_LOG_BACKEND_ACCENT_CLASS: Record<GcpLogBackendMode, string> = {
  logging_api: "border-l-[#FBBC04]",
  gcs: "border-l-[#FBBC04]",
};

export const GCP_LOG_BACKEND_OPTIONS: {
  mode: GcpLogBackendMode;
  label: string;
  summary: string;
  warning?: string;
}[] = [
  {
    mode: "logging_api",
    label: "Log Explorer (Direct API)",
    summary: "Reads logs directly from Cloud Logging.",
    warning: "About 60 log API requests per minute per project. Large kits may run slowly.",
  },
  {
    mode: "gcs",
    label: "Cloud Storage Archive",
    summary: "Reads log JSON objects from the configured GCS bucket using each collector's log filter.",
  },
];
