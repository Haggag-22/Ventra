export type DeploymentProfile = "platform" | "workstation" | "enterprise";

export type DeploymentProfileInfo = {
  id: DeploymentProfile;
  label: string;
  summary: string;
};

export const DEPLOYMENT_PROFILES: DeploymentProfileInfo[] = [
  {
    id: "platform",
    label: "Ventra Collector",
    summary: "Run collection from the Ventra console on the server",
  },
  {
    id: "workstation",
    label: "Workstation",
    summary: "Download a kit for the operator to run locally with cloud credentials",
  },
  {
    id: "enterprise",
    label: "Client Deployment",
    summary: "Download a kit for the client to run in their environment with extended collection",
  },
];

export function deploymentProfileLabel(id: string): string {
  if (id === "ec2" || id === "cloudshell") return "Workstation";
  return DEPLOYMENT_PROFILES.find((p) => p.id === id)?.label ?? id;
}

export function parseDeploymentProfile(raw: string | null | undefined): DeploymentProfile {
  const v = (raw || "platform").toLowerCase();
  if (v === "ec2") return "workstation";
  // Legacy kits saved as cloudshell were download-to-client flows, not server-side runs.
  if (v === "cloudshell") return "workstation";
  if (v === "ventra" || v === "ventra-collector" || v === "ventra_console") return "platform";
  return DEPLOYMENT_PROFILES.some((p) => p.id === v) ? (v as DeploymentProfile) : "platform";
}

export function isPlatformProfile(id: string): boolean {
  return id === "platform";
}

export function isDownloadProfile(id: string): boolean {
  return id === "workstation" || id === "enterprise";
}

export function isEnterpriseProfile(id: string): boolean {
  return id === "enterprise";
}

/** Kubernetes live console runs are disabled — kits are download-only until node collection is wired. */
export function supportsLiveConsoleRun(cloud: string): boolean {
  return cloud.trim().toLowerCase() !== "kubernetes";
}

/** Default kit profile for a cloud. Kubernetes always downloads a workstation kit. */
export function defaultDeploymentProfileForCloud(cloud: string): DeploymentProfile {
  return supportsLiveConsoleRun(cloud) ? "platform" : "workstation";
}

/** Coerce saved/requested profiles so Kubernetes never stays on live ``platform``. */
export function coerceDeploymentProfileForCloud(
  cloud: string,
  profile: string | null | undefined,
): DeploymentProfile {
  const parsed = parseDeploymentProfile(profile);
  if (!supportsLiveConsoleRun(cloud)) {
    return isPlatformProfile(parsed) ? "workstation" : parsed;
  }
  return parsed;
}
