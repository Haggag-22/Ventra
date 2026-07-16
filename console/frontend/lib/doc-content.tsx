import type { ReactNode } from "react";
import { AWS_COLLECTOR_PERMISSION_GROUPS } from "./aws-collector-permissions";
import { GCP_COLLECTOR_PERMISSION_GROUPS } from "./gcp-collector-permissions";
import type { DocProvider, DocSectionId } from "./docs-routes";

export type DocContentBlock =
  | { type: "p"; text: string }
  | { type: "ul"; items: string[] }
  | { type: "ol"; items: string[] }
  | { type: "code"; language?: string; code: string }
  | { type: "note"; text: string }
  | { type: "table"; headers: string[]; rows: string[][] };

export type DocSectionContent = {
  title: string;
  blocks: DocContentBlock[];
};

function permissionGroupSummary(
  groups: { label: string; actions: string[] }[],
): DocContentBlock[] {
  return [
    {
      type: "p",
      text: `Ventra collectors need read only access across ${groups.length} service areas. Each area maps to one or more collectors in Acquire, and the full action list lives in the downloadable policy files below.`,
    },
    {
      type: "ul",
      items: groups.map((g) => `${g.label} (${g.actions.length} actions)`),
    },
  ];
}

// ---- Amazon Web Services ---------------------------------------------------------------

const AWS_AUTH: DocSectionContent = {
  title: "Authentication",
  blocks: [
    {
      type: "p",
      text: "Ventra reaches AWS through an IAM identity that carries read only access. You save that identity once as a connection under Config, Providers, and Ventra reuses it for platform collection runs and for building acquisition kits. Nothing is stored in the browser.",
    },
    {
      type: "p",
      text: "The wizard offers two authentication methods on the Authentication method step. Choose the one that matches how the client grants access.",
    },
    {
      type: "table",
      headers: ["Method", "What you provide", "When to use"],
      rows: [
        [
          "Credentials",
          "Access Key ID, Secret Access Key, and an optional Session Token",
          "A dedicated IAM user, or temporary STS credentials issued for the engagement",
        ],
        [
          "IAM Role",
          "Role ARN",
          "Ventra assumes a cross account role using the base credentials already present on the Ventra host",
        ],
      ],
    },
    {
      type: "p",
      text: "Always create a dedicated collector identity. Never use personal administrator keys. Attach the Ventra read only policy, or deploy the CloudFormation stack or Terraform module linked on the Permissions page.",
    },
    {
      type: "ol",
      items: [
        "Create an IAM user or role called ventra collector and attach the read only policy.",
        "For the Credentials method, create an access key for that user.",
        "For the IAM Role method, note the role ARN and allow the Ventra host identity to assume it.",
        "Open Config, Providers and choose Add cloud connection, then select Amazon Web Services.",
        "On Provider details, enter a display name and the twelve digit account ID.",
        "On Authentication method, choose Credentials or IAM Role.",
        "On Authenticate, paste the access keys or the role ARN.",
        "Run Validate connection. A pass confirms Ventra can call the STS GetCallerIdentity API.",
      ],
    },
    {
      type: "note",
      text: "The Session Token is only needed for temporary credentials from STS AssumeRole. Permanent IAM user keys leave the Session Token field empty.",
    },
  ],
};

const AWS_PERMISSIONS: DocSectionContent = {
  title: "Permissions",
  blocks: [
    {
      type: "p",
      text: "Every Ventra AWS collector is strictly read only. The policies contain Describe, Get, List, Lookup, and Filter style actions only. No Create, Put, Delete, Update, Modify, Run, or Terminate action appears anywhere in the collector code or the reference policies.",
    },
    ...permissionGroupSummary(AWS_COLLECTOR_PERMISSION_GROUPS),
    {
      type: "p",
      text: "S3 object read access is scoped to the common log bucket name patterns, such as CloudTrail, VPC flow, and load balancer access logs. Your security team should map the resource entries to the buckets that actually hold logs in the account.",
    },
    {
      type: "note",
      text: "Send the plain text permission list to the client IAM administrator for review before the engagement. The JSON policy suits labs and quick validation.",
    },
  ],
};

const AWS_CONNECTIONS: DocSectionContent = {
  title: "Connections",
  blocks: [
    {
      type: "p",
      text: "A connection binds one AWS identity to a named scope inside the console. Ventra tests the connection when you save it, then reuses it across platform runs and Acquire kit builds.",
    },
    {
      type: "table",
      headers: ["Field", "Step", "Purpose"],
      rows: [
        ["Display name", "Provider details", "How the connection appears in dropdowns and run history"],
        ["Alias", "Provider details", "Optional short tag such as Production or Forensics account"],
        ["Account ID", "Provider details", "The twelve digit account identifier, used for labeling and validation"],
        ["Access Key ID and Secret Access Key", "Authenticate", "Long lived or temporary STS credentials for the Credentials method"],
        ["Session Token", "Authenticate", "Only for temporary credentials from an assumed role"],
        ["Role ARN", "Authenticate", "The cross account role Ventra assumes for the IAM Role method"],
      ],
    },
    {
      type: "p",
      text: "Platform runs collect inside the Ventra backend using the saved connection. Workstation and client kit profiles export a kit zip, and credentials never travel inside the kit. The operator supplies keys through the environment or the command line on the collection host.",
    },
    {
      type: "note",
      text: "When you edit a connection, leave the Secret Access Key blank to keep the value already saved on the server.",
    },
  ],
};

// ---- Google Cloud Platform -------------------------------------------------------------

const GCP_AUTH: DocSectionContent = {
  title: "Authentication",
  blocks: [
    {
      type: "p",
      text: "Ventra reaches Google Cloud with a service account that carries read only access, or with Application Default Credentials present on the Ventra host. Save the identity once as a connection, then reuse it for platform runs and kits.",
    },
    {
      type: "table",
      headers: ["Method", "What you provide", "When to use"],
      rows: [
        [
          "Service Account Key",
          "A service account JSON key",
          "Most engagements. Ventra keeps the key encrypted on the server",
        ],
        [
          "Application Default Credentials",
          "Nothing inside Ventra",
          "The Ventra host already carries collector credentials through the metadata server or a mounted key",
        ],
      ],
    },
    {
      type: "ol",
      items: [
        "Create a service account called ventra collector and a custom role with the read only methods, or bind the predefined read only roles.",
        "Grant the role on every project in scope, or bind once at the folder or organization level.",
        "Enable the Cloud Logging, Cloud Resource Manager, and Security Command Center APIs wherever you plan to collect.",
        "For the Service Account Key method, create a JSON key if your policy permits keys.",
        "Open Config, Providers, add a connection, and select Google Cloud Platform.",
        "On Provider details, set the project ID. For several projects, list them separated by commas.",
        "On Authenticate, paste or upload the service account key, or choose Application Default Credentials.",
        "Run Validate connection to confirm Ventra can reach the project.",
      ],
    },
    {
      type: "note",
      text: "Prefer a dedicated collector service account over a human Google account. Rotate or delete the key when the engagement ends.",
    },
  ],
};

const GCP_PERMISSIONS: DocSectionContent = {
  title: "Permissions",
  blocks: [
    {
      type: "p",
      text: "GCP access is granted as a custom role, or as predefined read only roles that cover the same API methods. The BigQuery jobs.create method is included so the log export backend can query partitioned audit tables.",
    },
    ...permissionGroupSummary(GCP_COLLECTOR_PERMISSION_GROUPS),
    {
      type: "note",
      text: "Download the plain text permission list for client review. The kit ships a narrowed copy under the iam folder, scoped to the collectors you selected.",
    },
  ],
};

const GCP_CONNECTIONS: DocSectionContent = {
  title: "Connections",
  blocks: [
    {
      type: "p",
      text: "A GCP connection stores the service account key encrypted on the server, together with the project scope. Authentication, which is who calls GCP, and scope, which is the projects to query, are separate inputs.",
    },
    {
      type: "table",
      headers: ["Field", "Step", "Purpose"],
      rows: [
        ["Project IDs", "Provider details", "The target projects for collection and validation, separated by commas"],
        ["Service account key JSON", "Authenticate", "Pasted or uploaded, or omitted when you use Application Default Credentials"],
        ["Principal email", "Recorded automatically", "Written to the run manifest, never the private key material"],
      ],
    },
    {
      type: "p",
      text: "When you leave the project field empty, Ventra falls back to the home project embedded in the service account key.",
    },
    {
      type: "note",
      text: "When you edit a connection, leave the key field blank to keep the key already saved on the server.",
    },
  ],
};

// ---- Microsoft Azure -------------------------------------------------------------------

const AZURE_AUTH: DocSectionContent = {
  title: "Authentication",
  blocks: [
    {
      type: "p",
      text: "Azure collection uses an Entra ID app registration, also called a service principal. Ventra acquires tokens for the Azure Resource Manager and Microsoft Graph APIs on the server. Resource Manager access attaches as a role on each subscription, and Graph access needs tenant administrator consent.",
    },
    {
      type: "table",
      headers: ["Field", "Where it comes from"],
      rows: [
        ["Tenant ID", "The Entra ID directory overview"],
        ["Client ID", "The app registration overview"],
        ["Client secret", "Certificates and secrets on the app registration"],
        ["Subscription ID", "The subscription you plan to collect"],
      ],
    },
    {
      type: "ol",
      items: [
        "Create an app registration in Entra ID and note the Tenant ID and Client ID.",
        "Create a client secret with an expiry that covers the engagement.",
        "Assign the read only role on the subscription, or deploy the Terraform module.",
        "Grant the Microsoft Graph application permissions and record tenant administrator consent.",
        "Open Config, Providers, add a connection, and select Microsoft Azure.",
        "Enter the Tenant ID, Client ID, client secret, and Subscription ID, then run Validate connection.",
      ],
    },
    {
      type: "note",
      text: "Sign in logs need an Entra ID P1 or P2 license. Ventra does not switch on audit feeds. Confirm ingestion is already active in the client tenant.",
    },
  ],
};

const AZURE_PERMISSIONS: DocSectionContent = {
  title: "Permissions",
  blocks: [
    {
      type: "p",
      text: "Azure access spans Resource Manager provider actions and Microsoft Graph application permissions. Every scope is read only.",
    },
    {
      type: "ul",
      items: [
        "Resource Manager read only: subscriptions, activity logs, network watchers, storage metadata, Key Vault inventory, AKS clusters, Defender alerts, and Log Analytics query.",
        "Microsoft Graph: AuditLog.Read.All, Directory.Read.All, User.Read.All, Group.Read.All, and Application.Read.All.",
      ],
    },
    {
      type: "p",
      text: "To read diagnostic and flow log blobs from storage accounts, grant Storage Blob Data Reader or an equivalent data action on the accounts that hold the logs.",
    },
  ],
};

const AZURE_CONNECTIONS: DocSectionContent = {
  title: "Connections",
  blocks: [
    {
      type: "p",
      text: "An Azure connection uses the app registration credentials. The Provider details step captures the subscription scope and an optional alias. The Authenticate step stores the tenant ID, client ID, and client secret on the server.",
    },
    {
      type: "table",
      headers: ["Field", "Step", "Purpose"],
      rows: [
        ["Subscription ID", "Provider details", "The Resource Manager scope for Azure resource collectors"],
        ["Alias", "Provider details", "Optional short label shown in the connections table"],
        ["Tenant ID", "Authenticate", "The Entra directory identifier"],
        ["Client ID", "Authenticate", "The application ID from the app registration"],
        ["Client secret", "Authenticate", "Created under Certificates and secrets, omitted on edit to keep the saved value"],
      ],
    },
  ],
};

// ---- Kubernetes (roadmap; left as-is for now) ------------------------------------------

const K8S_AUTH: DocSectionContent = {
  title: "Authentication",
  blocks: [
    {
      type: "p",
      text: "Ventra Kubernetes connections authenticate with a kubeconfig file and a named context. Paste the full kubeconfig YAML on the authenticate step; Ventra validates the YAML and confirms the context exists before saving.",
    },
    {
      type: "ul",
      items: [
        "Kubernetes Context: the context name from your kubeconfig (provider details step).",
        "Kubeconfig Content: full kubeconfig YAML pasted server-side (authenticate step).",
        "Provider alias: optional short label shown in the connections table.",
        "On edit, leave kubeconfig blank to keep the saved content.",
      ],
    },
  ],
};

const K8S_PERMISSIONS: DocSectionContent = {
  title: "Permissions",
  blocks: [
    {
      type: "p",
      text: "Grant read-only RBAC to the identity in your kubeconfig. Required verbs are get, list, and watch on core workloads, events, and audit-related API groups. No create, update, patch, or delete permissions are required.",
    },
  ],
};

const K8S_CONNECTIONS: DocSectionContent = {
  title: "Connections",
  blocks: [
    {
      type: "p",
      text: "Create a Kubernetes connection from Config → Providers. Step 1 selects Kubernetes; step 2 sets the display name, optional alias, and context name; step 3 stores the kubeconfig YAML. The validate step runs a structural check (YAML parse + context lookup) before save.",
    },
  ],
};

const CONTENT: Partial<Record<DocProvider, Partial<Record<DocSectionId, DocSectionContent>>>> = {
  aws: {
    authentication: AWS_AUTH,
    permissions: AWS_PERMISSIONS,
    connections: AWS_CONNECTIONS,
  },
  gcp: {
    authentication: GCP_AUTH,
    permissions: GCP_PERMISSIONS,
    connections: GCP_CONNECTIONS,
  },
  azure: {
    authentication: AZURE_AUTH,
    permissions: AZURE_PERMISSIONS,
    connections: AZURE_CONNECTIONS,
  },
  kubernetes: {
    authentication: K8S_AUTH,
    permissions: K8S_PERMISSIONS,
    connections: K8S_CONNECTIONS,
  },
};

export function docSectionContent(
  provider: DocProvider,
  section: DocSectionId,
): DocSectionContent | null {
  return CONTENT[provider]?.[section] ?? null;
}

export function renderDocBlocks(blocks: DocContentBlock[]): ReactNode[] {
  return blocks.map((block, index) => {
    switch (block.type) {
      case "p":
        return (
          <p key={index} className="leading-relaxed text-fg-subtle">
            {block.text}
          </p>
        );
      case "ul":
        return (
          <ul key={index} className="list-disc space-y-1.5 pl-5 text-fg-subtle">
            {block.items.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        );
      case "ol":
        return (
          <ol key={index} className="list-decimal space-y-1.5 pl-5 text-fg-subtle">
            {block.items.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ol>
        );
      case "code":
        return (
          <pre
            key={index}
            className="overflow-x-auto rounded-lg border border-border bg-bg px-4 py-3 font-mono text-xs leading-relaxed text-fg"
          >
            <code>{block.code}</code>
          </pre>
        );
      case "note":
        return (
          <p
            key={index}
            className="rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-fg-subtle"
          >
            {block.text}
          </p>
        );
      case "table":
        return (
          <div key={index} className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-surface-2">
                <tr>
                  {block.headers.map((h) => (
                    <th key={h} className="px-3 py-2 font-medium text-fg">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {block.rows.map((row, ri) => (
                  <tr key={ri} className="border-b border-border last:border-0">
                    {row.map((cell, ci) => (
                      <td key={ci} className="px-3 py-2 text-fg-subtle">
                        {cell}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      default:
        return null;
    }
  });
}
