export type DeploymentProfile = "cloudshell" | "workstation" | "enterprise";

export type DeploymentProfileInfo = {
  id: DeploymentProfile;
  label: string;
  summary: string;
};

export const DEPLOYMENT_PROFILES: DeploymentProfileInfo[] = [
  {
    id: "cloudshell",
    label: "Cloud Shell",
    summary: "Run inside the client's Cloud Shell session",
  },
  {
    id: "workstation",
    label: "Workstation",
    summary: "Operator runs the kit on a local machine with cloud credentials",
  },
  {
    id: "enterprise",
    label: "Enterprise",
    summary: "Complete collection in your time window, no record cap, S3 handoff",
  },
];

export function deploymentProfileLabel(id: string): string {
  if (id === "ec2") return "Workstation";
  return DEPLOYMENT_PROFILES.find((p) => p.id === id)?.label ?? id;
}

export function parseDeploymentProfile(raw: string | null | undefined): DeploymentProfile {
  const v = (raw || "cloudshell").toLowerCase();
  if (v === "ec2") return "workstation";
  return DEPLOYMENT_PROFILES.some((p) => p.id === v) ? (v as DeploymentProfile) : "cloudshell";
}

export function isEnterpriseProfile(id: string): boolean {
  return id === "enterprise";
}
