import type { DocProvider } from "./docs-routes";

export type DeploymentTemplateKind = "cloudformation" | "terraform" | "arm" | "policy";

export type DeploymentTemplate = {
  id: string;
  label: string;
  kind: DeploymentTemplateKind;
  href: string;
  filename: string;
  description?: string;
};

const PUBLIC = "/docs/deployment";
const POLICIES = "/docs/iam-policies";

export const PROVIDER_DEPLOYMENT_TEMPLATES: Partial<Record<DocProvider, DeploymentTemplate[]>> = {
  aws: [
    {
      id: "aws-cfn",
      label: "CloudFormation template",
      kind: "cloudformation",
      href: `${PUBLIC}/aws/cloudformation/ventra-collector-iam.yaml`,
      filename: "ventra-collector-iam.yaml",
      description: "Creates a read-only IAM user, managed policy, and optional access key.",
    },
    {
      id: "aws-tf",
      label: "Terraform code",
      kind: "terraform",
      href: `${PUBLIC}/aws/terraform/main.tf`,
      filename: "main.tf",
      description: "Terraform module for the Ventra collector IAM user and policy.",
    },
    {
      id: "aws-policy-json",
      label: "IAM policy JSON",
      kind: "policy",
      href: `${POLICIES}/aws-collector-readonly.json`,
      filename: "aws-collector-readonly.json",
    },
    {
      id: "aws-policy-txt",
      label: "Permission reference",
      kind: "policy",
      href: `${POLICIES}/aws-collector-permissions.txt`,
      filename: "aws-collector-permissions.txt",
    },
  ],
  gcp: [
    {
      id: "gcp-tf",
      label: "Terraform code",
      kind: "terraform",
      href: `${PUBLIC}/gcp/terraform/main.tf`,
      filename: "main.tf",
      description: "Service account, custom role, and project IAM bindings.",
    },
    {
      id: "gcp-policy-json",
      label: "Permission list JSON",
      kind: "policy",
      href: `${POLICIES}/gcp-collector-readonly.json`,
      filename: "gcp-collector-readonly.json",
    },
    {
      id: "gcp-policy-txt",
      label: "Permission reference",
      kind: "policy",
      href: `${POLICIES}/gcp-collector-permissions.txt`,
      filename: "gcp-collector-permissions.txt",
    },
  ],
  azure: [
    {
      id: "azure-tf",
      label: "Terraform code",
      kind: "terraform",
      href: `${PUBLIC}/azure/terraform/main.tf`,
      filename: "main.tf",
      description: "Custom ARM role definition and subscription assignment.",
    },
    {
      id: "azure-arm-readonly",
      label: "ARM read-only policy",
      kind: "policy",
      href: `${POLICIES}/azure-collector-readonly.json`,
      filename: "azure-collector-readonly.json",
    },
    {
      id: "azure-graph",
      label: "Microsoft Graph permissions",
      kind: "policy",
      href: `${POLICIES}/azure-collector-graph.json`,
      filename: "azure-collector-graph.json",
    },
  ],
  kubernetes: [
    {
      id: "k8s-rbac-yaml",
      label: "RBAC ClusterRole",
      kind: "policy",
      href: `${POLICIES}/kubernetes-collector-readonly.yaml`,
      filename: "kubernetes-collector-readonly.yaml",
      description: "ServiceAccount, read-only ClusterRole, and ClusterRoleBinding.",
    },
    {
      id: "k8s-rbac-json",
      label: "RBAC permissions JSON",
      kind: "policy",
      href: `${POLICIES}/kubernetes-collector-readonly.json`,
      filename: "kubernetes-collector-readonly.json",
    },
  ],
};

/** IaC templates shown in the auth wizard (excludes plain policy JSON). */
export function authWizardTemplates(provider: DocProvider): DeploymentTemplate[] {
  return (PROVIDER_DEPLOYMENT_TEMPLATES[provider] ?? []).filter(
    (t) => t.kind === "cloudformation" || t.kind === "terraform",
  );
}

export function deploymentTemplatesForProvider(provider: DocProvider): DeploymentTemplate[] {
  return PROVIDER_DEPLOYMENT_TEMPLATES[provider] ?? [];
}
