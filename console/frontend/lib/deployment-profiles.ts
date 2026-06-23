export type DeploymentProfile = "cloudshell" | "workstation" | "ec2";

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
    id: "ec2",
    label: "EC2 / VM",
    summary: "Dedicated VM in the client account for large pulls",
  },
];

export function deploymentProfileLabel(id: string): string {
  return DEPLOYMENT_PROFILES.find((p) => p.id === id)?.label ?? id;
}

export function parseDeploymentProfile(raw: string | null | undefined): DeploymentProfile {
  const v = (raw || "cloudshell").toLowerCase();
  return DEPLOYMENT_PROFILES.some((p) => p.id === v) ? (v as DeploymentProfile) : "cloudshell";
}
