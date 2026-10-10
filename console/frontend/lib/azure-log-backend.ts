/** Azure Activity Log source — mirrors acquisition.yaml ``azure_log_backend``. */

export type AzureLogBackendMode = "monitor_api" | "storage";

export type AzureLogBackendConfig = {
  mode: AzureLogBackendMode;
};

export const AZURE_ACTIVITY_LOG_COLLECTOR = "activity_log";

export function cartNeedsAzureLogBackend(collectors: string[]): boolean {
  return collectors.includes(AZURE_ACTIVITY_LOG_COLLECTOR);
}

export type AzureLogBackendFormState = {
  mode: AzureLogBackendMode | "";
};

export const DEFAULT_AZURE_LOG_BACKEND_FORM: AzureLogBackendFormState = {
  mode: "",
};

export function azureConfigToForm(cfg?: AzureLogBackendConfig | null): AzureLogBackendFormState {
  const mode = cfg?.mode;
  if (mode === "storage" || mode === "monitor_api") return { mode };
  return { ...DEFAULT_AZURE_LOG_BACKEND_FORM };
}

export function serializeAzureLogBackend(
  form: AzureLogBackendFormState,
): AzureLogBackendConfig | undefined {
  if (form.mode !== "storage" && form.mode !== "monitor_api") return undefined;
  return { mode: form.mode };
}

/** Returns an error when Activity Logs are in the kit and no source is chosen. */
export function validateAzureLogBackendForm(
  form: AzureLogBackendFormState,
  needsStrategy: boolean,
): string | null {
  if (!needsStrategy) return null;
  if (!form.mode) return "Choose how Azure Activity Logs should be collected.";
  return null;
}

export const AZURE_LOG_BACKEND_OPTIONS: {
  mode: AzureLogBackendMode;
  label: string;
  summary: string;
  warning?: string;
}[] = [
  {
    mode: "monitor_api",
    label: "Monitor API",
    summary: "Reads the platform Activity Log for about 90 days.",
    warning: "50 queries per 30 seconds. A busy subscription or several subscriptions can make this slow.",
  },
  {
    mode: "storage",
    label: "Storage account archive",
    summary:
      "Finds the subscription diagnostic setting and reads Activity Log blobs from the storage account it names.",
    warning:
      "The export has to already exist. Blobs start when the setting was turned on, so they can be shorter than the 90-day API window.",
  },
];
