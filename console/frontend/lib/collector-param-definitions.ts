/** Auto-generated collector parameter schemas for Acquire UI. */

export type ParamFieldType = "string" | "list" | "boolean";

export interface ParamFieldDef {
  key: string;
  label: string;
  type: ParamFieldType;
  description?: string;
  docUrl?: string;
  required?: boolean;
  placeholder?: string;
}

const AZURE_ACTIVITY_LOG =
  "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log";
const AZURE_RESOURCE_GRAPH =
  "https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language";
const AWS_CLOUDTRAIL_EVENTS =
  "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html";
const GCP_VPC_FLOW = "https://cloud.google.com/vpc/docs/using-flow-logs";
const AWS_GUARDDUTY =
  "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html";
const ENTRA_SIGNIN =
  "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins-log-events";

export const COLLECTOR_PARAM_SCHEMAS: Record<string, ParamFieldDef[]> = {
  activity_log: [
    {
      key: "resource_group_names",
      label: "Resource group names",
      type: "list",
      description:
        "Limit Activity Log collection to specific Azure resource groups by name. Leave empty to scan all groups in the subscription.",
    },
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description:
        "Full Azure Resource Manager IDs of resources whose Activity Log entries should be collected (e.g. /subscriptions/.../resourceGroups/.../providers/...).",
      docUrl: AZURE_ACTIVITY_LOG,
    },
    {
      key: "caller",
      label: "Caller",
      type: "list",
      description:
        "Filter by caller identity — user principal name, object ID, or service principal that initiated the operation.",
    },
    {
      key: "correlation_id",
      label: "Correlation ID",
      type: "list",
      description:
        "Collect entries tied to a specific correlation ID, useful when tracing a single multi-step Azure operation.",
    },
    {
      key: "event_categories",
      label: "Event categories",
      type: "list",
      description:
        "Filter by Activity Log category such as Administrative, Policy, Security, ServiceHealth, or Alert.",
      docUrl: AZURE_ACTIVITY_LOG,
    },
    {
      key: "operation_names",
      label: "Operation names",
      type: "list",
      description:
        "Filter by Azure operation name (e.g. Microsoft.Compute/virtualMachines/write or Microsoft.Network/networkSecurityGroups/delete).",
    },
  ],
  aks_audit: [
    {
      key: "cluster_names",
      label: "Cluster names",
      type: "list",
      description: "AKS cluster names to include. Matches the name shown in the Azure portal.",
    },
    {
      key: "cluster_ids",
      label: "Cluster IDs",
      type: "list",
      description: "Full ARM resource IDs of AKS clusters to scope audit log collection.",
    },
  ],
  cloud_armor: [
    {
      key: "security_policy_names",
      label: "Security policy names",
      type: "list",
      description: "Cloud Armor security policy names to scope inventory and enforced request logs.",
    },
    {
      key: "security_policy_ids",
      label: "Security policy IDs",
      type: "list",
      description: "Numeric Cloud Armor security policy IDs to filter collection.",
    },
    {
      key: "backend_service_names",
      label: "Backend service names",
      type: "list",
      description: "Backend service names attached to Cloud Armor policies to narrow request logs.",
    },
  ],
  cloud_dns: [
    {
      key: "dns_zone_names",
      label: "DNS zone names",
      type: "list",
      description: "Cloud DNS managed zone names to filter DNS query logs.",
    },
  ],
  cloud_nat: [
    {
      key: "regions",
      label: "Regions",
      type: "list",
      description: "GCP regions to scope Cloud NAT log collection.",
    },
    {
      key: "nat_gateway_names",
      label: "NAT gateway names",
      type: "list",
      description: "Cloud NAT gateway names to filter translation logs.",
    },
    {
      key: "src_ip",
      label: "Source IP",
      type: "list",
      description: "Internal source IP addresses to filter Cloud NAT logs (jsonPayload.connection.src_ip).",
    },
    {
      key: "dest_ip",
      label: "Destination IP",
      type: "list",
      description: "External destination IP addresses to filter Cloud NAT logs (jsonPayload.connection.dest_ip).",
    },
  ],
  api_gateway: [
    {
      key: "gateway_ids",
      label: "Gateway IDs",
      type: "list",
      description: "GCP API Gateway gateway IDs to collect access and audit logs from.",
    },
  ],
  app_gateway: [
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description: "Full ARM resource IDs of Application Gateways whose diagnostic logs should be collected.",
    },
    {
      key: "resource_group_names",
      label: "Resource group names",
      type: "list",
      description: "Azure resource groups containing Application Gateways to include.",
    },
  ],
  azure_firewall: [
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description: "Full ARM resource IDs of Azure Firewall instances to collect network and application rule logs from.",
    },
    {
      key: "firewall_names",
      label: "Firewall names",
      type: "list",
      description: "Azure Firewall resource names as shown in the portal.",
    },
  ],
  cloud_audit_admin: [
    {
      key: "service_names",
      label: "Service names",
      type: "list",
      description: "GCP API service names to include in Admin Activity audit log collection (e.g. iam.googleapis.com).",
    },
    {
      key: "method_names",
      label: "Method names",
      type: "list",
      description: "Specific Admin Activity API method names to filter on (e.g. google.iam.admin.v1.CreateServiceAccount).",
    },
    {
      key: "principal_email",
      label: "Principal email",
      type: "list",
      description: "Filter Admin Activity logs by the email of the user or service account that performed the action.",
    },
    {
      key: "resource_names",
      label: "Resource names",
      type: "list",
      description: "Filter by affected GCP resource name as recorded in the audit log protoPayload.",
    },
  ],
  cloud_audit_data: [
    {
      key: "service_names",
      label: "Service names",
      type: "list",
      description: "GCP API service names to include in Data Access audit log collection.",
    },
    {
      key: "resource_names",
      label: "Resource names",
      type: "list",
      description: "Filter Data Access logs by affected GCP resource name.",
    },
    {
      key: "principal_email",
      label: "Principal email",
      type: "list",
      description: "Filter by the email of the principal that read or modified data.",
    },
  ],
  cloud_audit_system: [
    {
      key: "resource_types",
      label: "Resource types",
      type: "list",
      description: "GCP resource types to include in System Event audit log collection (e.g. gce_instance).",
    },
    {
      key: "instance_ids",
      label: "Instance IDs",
      type: "list",
      description: "Compute Engine instance IDs to scope System Event audit logs.",
    },
  ],
  cloud_functions: [
    {
      key: "function_names",
      label: "Function names",
      type: "list",
      description: "Cloud Functions (Gen 1 or Gen 2) names to collect execution and audit logs from.",
    },
    {
      key: "regions",
      label: "Regions",
      type: "list",
      description: "GCP regions to scope function log collection (e.g. us-central1).",
    },
  ],
  cloud_monitoring: [
    {
      key: "alert_policy_names",
      label: "Alert policy names",
      type: "list",
      description: "Cloud Monitoring alert policy display names to include in incident collection.",
    },
    {
      key: "incident_ids",
      label: "Incident IDs",
      type: "list",
      description: "Specific Monitoring incident IDs to collect when investigating a known alert firing.",
    },
  ],
  apigateway: [
    {
      key: "api_ids",
      label: "API IDs",
      type: "list",
      description: "API Gateway REST or HTTP API IDs whose stage access logs should be collected.",
    },
    {
      key: "api_names",
      label: "API names",
      type: "list",
      description: "API Gateway API display names to scope access log collection.",
    },
    {
      key: "stage_names",
      label: "Stage names",
      type: "list",
      description: "Deployment stage names (e.g. prod, dev) to filter access log collection.",
    },
    {
      key: "log_group_names",
      label: "Log group names",
      type: "list",
      description: "CloudWatch Logs log group names where API Gateway access logs are delivered.",
    },
  ],
  cloudfront: [
    {
      key: "distribution_ids",
      label: "Distribution IDs",
      type: "list",
      description: "CloudFront distribution IDs (e.g. E1234ABCD5678) to collect access and real-time logs from.",
    },
    {
      key: "domain_names",
      label: "Domain names",
      type: "list",
      description: "Alternate domain names (CNAMEs) associated with distributions to filter on.",
    },
  ],
  cloudtrail: [
    {
      key: "trail_arns",
      label: "Trail ARNs",
      type: "list",
      description:
        "CloudTrail trail ARNs to collect from. Use when you know the exact trail resource in the account or organization.",
    },
    {
      key: "trail_names",
      label: "Trail names",
      type: "list",
      description: "Trail name as shown in the CloudTrail console. Matches trails in the current account or region scope.",
    },
    {
      key: "s3_bucket_names",
      label: "S3 bucket names",
      type: "list",
      description: "S3 buckets where CloudTrail log files are delivered. Useful when collecting directly from delivery storage.",
    },
    {
      key: "s3_prefixes",
      label: "S3 prefixes",
      type: "list",
      description: "S3 key prefix under the delivery bucket where trail objects are stored (e.g. AWSLogs/123456789012/CloudTrail/).",
    },
    {
      key: "event_names",
      label: "Event names",
      type: "list",
      description:
        "Filter CloudTrail records by eventName (e.g. ConsoleLogin, AssumeRole, PutBucketPolicy). Case-sensitive.",
      docUrl: AWS_CLOUDTRAIL_EVENTS,
    },
    {
      key: "username",
      label: "Username",
      type: "list",
      description: "Filter by IAM username in userIdentity.userName for human IAM users.",
    },
    {
      key: "user_identity_arn",
      label: "User identity ARN",
      type: "list",
      description:
        "Filter by principal ARN in userIdentity.arn (e.g. arn:aws:iam::123456789012:user/alice or a role session ARN).",
    },
  ],
  config: [
    {
      key: "config_rule_names",
      label: "Config rule names",
      type: "list",
      description: "AWS Config rule names to scope compliance and configuration change history.",
    },
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description: "AWS resource IDs (as recorded by Config) to limit configuration snapshots and compliance evaluations.",
    },
  ],
  defender: [
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description: "Azure resource IDs associated with Microsoft Defender for Cloud alerts or recommendations.",
    },
    {
      key: "severity",
      label: "Severity levels",
      type: "list",
      description: "Filter Defender findings by severity label (e.g. High, Medium, Low, Informational).",
    },
  ],
  detective: [
    {
      key: "graph_arns",
      label: "Graph ARNs",
      type: "list",
      description: "Amazon Detective behavior graph ARNs to scope investigation data collection.",
    },
    {
      key: "investigation_ids",
      label: "Investigation IDs",
      type: "list",
      description: "Specific Detective investigation IDs when collecting artifacts for an open case.",
    },
  ],
  diag_posture: [
    {
      key: "resource_group_names",
      label: "Resource group names",
      type: "list",
      description: "Resource groups to assess for diagnostic settings coverage and logging posture.",
    },
    {
      key: "source_ids",
      label: "Source IDs",
      type: "list",
      description: "ARM resource IDs of Azure resources to evaluate for missing or misconfigured diagnostic settings.",
    },
  ],
  dns: [
    {
      key: "dns_zone_ids",
      label: "DNS zone IDs",
      type: "list",
      description: "Route 53 hosted zone IDs to collect DNS query logs from.",
    },
    {
      key: "resolver_endpoint_ids",
      label: "Resolver endpoint IDs",
      type: "list",
      description: "Route 53 Resolver endpoint IDs for inbound/outbound DNS query logging.",
    },
  ],
  ec2: [
    {
      key: "instance_ids",
      label: "Instance IDs",
      type: "list",
      description: "EC2 instance IDs (e.g. i-0abc123def456) to collect instance metadata and related artifacts from.",
    },
    {
      key: "vpc_ids",
      label: "VPC IDs",
      type: "list",
      description: "VPC IDs to scope EC2 inventory and network-related collection.",
    },
    {
      key: "security_group_ids",
      label: "Security group IDs",
      type: "list",
      description: "Security group IDs to filter EC2 instances and their effective network rules.",
    },
    {
      key: "snapshot_ids",
      label: "Snapshot IDs",
      type: "list",
      description: "EBS snapshot IDs to include when collecting disk-related forensic artifacts.",
    },
    {
      key: "include_user_data",
      label: "Include user data",
      type: "boolean",
      description:
        "When enabled, includes EC2 instance user data scripts in collection. May contain secrets — use only when needed for investigation.",
    },
  ],
  gce: [
    {
      key: "instance_ids",
      label: "Instance IDs",
      type: "list",
      description: "Compute Engine instance IDs to include in GCE inventory collection.",
    },
    {
      key: "zones",
      label: "Zones",
      type: "list",
      description: "GCP zones (e.g. us-central1-a) to scope instance and disk inventory.",
    },
    {
      key: "network_names",
      label: "VPC / network names",
      type: "list",
      description: "VPC network names or self-links to filter instances by attached network.",
    },
    {
      key: "snapshot_ids",
      label: "Snapshot IDs",
      type: "list",
      description: "Persistent disk snapshot IDs to include in the snapshot inventory.",
    },
  ],
  gke_audit: [
    {
      key: "cluster_names",
      label: "Cluster names",
      type: "list",
      description: "GKE cluster names whose Kubernetes API audit logs should be collected.",
    },
    {
      key: "cluster_ids",
      label: "Cluster IDs",
      type: "list",
      description: "Full resource IDs or self-links of GKE clusters to scope audit log collection.",
    },
    {
      key: "locations",
      label: "Locations",
      type: "list",
      description: "GCP regions or zones where GKE clusters run (e.g. us-central1, europe-west1-b).",
    },
  ],
  eks_audit: [
    {
      key: "cluster_names",
      label: "Cluster names",
      type: "list",
      description: "EKS cluster names whose control plane audit logs should be collected.",
    },
    {
      key: "cluster_arns",
      label: "Cluster ARNs",
      type: "list",
      description: "Full ARNs of EKS clusters to scope audit log collection.",
    },
    {
      key: "log_group_names",
      label: "Log group names",
      type: "list",
      description: "CloudWatch Logs log group names where EKS audit logs are stored, if not using the default naming pattern.",
    },
  ],
  elb_alb: [
    {
      key: "load_balancer_arns",
      label: "Load balancer ARNs",
      type: "list",
      description: "Application or Network Load Balancer ARNs to collect access logs and configuration from.",
    },
    {
      key: "load_balancer_names",
      label: "Load balancer names",
      type: "list",
      description: "Load balancer names as shown in the EC2 console.",
    },
    {
      key: "s3_bucket_names",
      label: "Access log bucket names",
      type: "list",
      description: "S3 buckets where ELB/ALB access logs are delivered.",
    },
  ],
  entra_audit: [
    {
      key: "operation_names",
      label: "Operation names",
      type: "list",
      description: "Microsoft Entra audit log operation names to filter on (e.g. Add member to group, Consent to application).",
    },
    {
      key: "category",
      label: "Categories",
      type: "list",
      description: "Entra audit log categories such as ApplicationManagement, UserManagement, or Policy.",
    },
  ],
  entra_directory: [
    {
      key: "user_ids",
      label: "User IDs",
      type: "list",
      description: "Entra object IDs of users to scope directory object collection.",
    },
    {
      key: "group_ids",
      label: "Group IDs",
      type: "list",
      description: "Entra object IDs of groups to include in directory collection.",
    },
    {
      key: "app_ids",
      label: "App IDs",
      type: "list",
      description: "Application (client) IDs of enterprise apps and service principals to collect.",
    },
  ],
  entra_signin: [
    {
      key: "user_principal_names",
      label: "User principal names",
      type: "list",
      description: "User principal names (UPNs) to filter sign-in logs, e.g. alice@contoso.com.",
      docUrl: ENTRA_SIGNIN,
    },
    {
      key: "user_ids",
      label: "User IDs",
      type: "list",
      description: "Entra object IDs of users whose sign-in events should be collected.",
    },
    {
      key: "app_ids",
      label: "App IDs",
      type: "list",
      description: "Application IDs involved in sign-in events to filter on.",
    },
    {
      key: "ip_address",
      label: "IP addresses",
      type: "list",
      description: "Source IP addresses recorded in sign-in logs for lateral movement or compromise investigations.",
    },
  ],
  firewall_logs: [
    {
      key: "firewall_rule_names",
      label: "Firewall rule names",
      type: "list",
      description: "GCP VPC firewall rule names to filter firewall log entries.",
    },
    {
      key: "src_ip",
      label: "Source IP",
      type: "list",
      description: "Source IP addresses to filter VPC firewall logs.",
    },
  ],
  front_door: [
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description: "Full ARM resource IDs of Azure Front Door profiles or classic Front Door resources.",
    },
    {
      key: "profile_names",
      label: "Profile names",
      type: "list",
      description: "Front Door profile names as shown in the Azure portal.",
    },
  ],
  guardduty: [
    {
      key: "finding_ids",
      label: "Finding IDs",
      type: "list",
      description: "Specific GuardDuty finding IDs to collect when investigating known alerts.",
    },
    {
      key: "detector_ids",
      label: "Detector IDs",
      type: "list",
      description: "GuardDuty detector IDs for the account or region scope.",
    },
    {
      key: "finding_types",
      label: "Finding types",
      type: "list",
      description: "GuardDuty finding type identifiers (e.g. UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration).",
      docUrl: AWS_GUARDDUTY,
    },
    {
      key: "resource_arns",
      label: "Resource ARNs",
      type: "list",
      description: "AWS resource ARNs referenced in GuardDuty findings to filter on.",
    },
    {
      key: "severity_min",
      label: "Severity min",
      type: "string",
      description:
        "Minimum GuardDuty finding severity score from 1 (low) to 8 (critical). Findings below this threshold are excluded.",
      placeholder: "5",
      docUrl: AWS_GUARDDUTY,
    },
  ],
  iam: [
    {
      key: "user_names",
      label: "User names",
      type: "list",
      description: "IAM user names to scope identity inventory and policy attachment collection.",
    },
    {
      key: "role_names",
      label: "Role names",
      type: "list",
      description: "IAM role names to include in collection.",
    },
    {
      key: "role_arns",
      label: "Role ARNs",
      type: "list",
      description: "Full IAM role ARNs to filter identity artifacts.",
    },
    {
      key: "policy_arns",
      label: "Policy ARNs",
      type: "list",
      description: "Managed or customer-managed policy ARNs to scope policy document collection.",
    },
    {
      key: "include_credential_report",
      label: "Include credential report",
      type: "boolean",
      description:
        "When enabled, downloads the IAM credential report for the account. Useful for stale access key and MFA gap analysis.",
    },
  ],
  iam_policy: [
    {
      key: "roles",
      label: "Roles",
      type: "list",
      description: "GCP IAM role names or paths to scope policy binding collection.",
    },
    {
      key: "members",
      label: "Members",
      type: "list",
      description: "IAM member strings (user:, serviceAccount:, group:) to filter policy bindings involving specific principals.",
    },
  ],
  inspector2: [
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description: "AWS resource IDs with Inspector findings to scope vulnerability collection.",
    },
    {
      key: "ecr_repository_names",
      label: "ECR repository names",
      type: "list",
      description: "Amazon ECR repository names to filter container image scan findings.",
    },
  ],
  key_vault: [
    {
      key: "vault_ids",
      label: "Vault IDs",
      type: "list",
      description: "Full ARM resource IDs of Azure Key Vault instances.",
    },
    {
      key: "vault_names",
      label: "Vault names",
      type: "list",
      description: "Key Vault names as shown in the Azure portal.",
    },
  ],
  kms: [
    {
      key: "key_ids",
      label: "Key IDs",
      type: "list",
      description: "KMS key IDs (UUID form) to scope key metadata and usage collection.",
    },
    {
      key: "key_arns",
      label: "Key ARNs",
      type: "list",
      description: "Full KMS key ARNs to filter cryptographic key artifacts.",
    },
    {
      key: "alias_names",
      label: "Alias names",
      type: "list",
      description: "KMS alias names (e.g. alias/prod/database) to resolve and collect associated keys.",
    },
  ],
  lambda: [
    {
      key: "function_names",
      label: "Function names",
      type: "list",
      description: "Lambda function names to collect configuration and execution-related artifacts from.",
    },
    {
      key: "function_arns",
      label: "Function ARNs",
      type: "list",
      description: "Full Lambda function ARNs to scope collection.",
    },
  ],
  lambda_logs: [
    {
      key: "function_names",
      label: "Function names",
      type: "list",
      description: "Lambda function names whose CloudWatch execution logs should be collected.",
    },
    {
      key: "function_arns",
      label: "Function ARNs",
      type: "list",
      description: "Full Lambda function ARNs to scope log collection.",
    },
    {
      key: "log_group_names",
      label: "Log group names",
      type: "list",
      description: "CloudWatch Logs group names (typically /aws/lambda/<name>) to collect from directly.",
    },
  ],
  load_balancer: [
    {
      key: "url_map_names",
      label: "URL map names",
      type: "list",
      description: "GCP URL map names associated with external HTTP(S) load balancers.",
    },
    {
      key: "backend_service_names",
      label: "Backend service names",
      type: "list",
      description: "Backend service names to filter load balancer logging and configuration.",
    },
  ],
  cloud_cdn: [
    {
      key: "url_map_names",
      label: "URL map names",
      type: "list",
      description: "GCP URL map names associated with CDN-enabled HTTP(S) load balancers.",
    },
    {
      key: "backend_service_names",
      label: "Backend service names",
      type: "list",
      description: "Backend service names with Cloud CDN enabled to filter cache request logs.",
    },
  ],
  log_analytics: [
    {
      key: "workspace_ids",
      label: "Workspace IDs",
      type: "list",
      description: "Log Analytics workspace resource IDs to query tables and saved searches from.",
    },
    {
      key: "resource_ids",
      label: "Resource IDs",
      type: "list",
      description: "Azure resource IDs linked to Log Analytics data sources to scope queries.",
    },
  ],
  login_events: [
    {
      key: "principal_email",
      label: "Principal email",
      type: "list",
      description: "GCP principal email addresses to filter login and authentication audit events.",
    },
    {
      key: "source_ip",
      label: "Source IP",
      type: "list",
      description: "Source IP addresses recorded in GCP login audit events.",
    },
  ],
  logging_posture: [
    {
      key: "project_ids",
      label: "Project IDs",
      type: "list",
      description:
        "GCP project IDs to scope logging posture checks. Leave empty to use all projects in the acquisition.",
    },
  ],
  macie: [
    {
      key: "finding_ids",
      label: "Finding IDs",
      type: "list",
      description: "Amazon Macie finding IDs to collect for data exfiltration or sensitive data exposure investigations.",
    },
    {
      key: "resource_arns",
      label: "S3 bucket ARNs",
      type: "list",
      description: "S3 bucket ARNs referenced in Macie findings to filter on.",
    },
  ],
  nsg_flow: [
    {
      key: "nsg_resource_ids",
      label: "NSG resource IDs",
      type: "list",
      description: "ARM resource IDs of Network Security Groups whose flow logs should be collected.",
    },
    {
      key: "storage_account_ids",
      label: "Storage account IDs",
      type: "list",
      description: "Storage accounts where NSG flow logs are written.",
    },
  ],
  network_posture: [
    {
      key: "network_names",
      label: "VPC / network names",
      type: "list",
      description: "VPC network names or self-links to scope firewall rules, subnets, and routes.",
    },
    {
      key: "vpc_ids",
      label: "VPC IDs",
      type: "list",
      description: "Alias for network names — filter network posture by VPC identifier or self-link.",
    },
    {
      key: "firewall_rule_names",
      label: "Firewall rule names",
      type: "list",
      description: "VPC firewall rule names to include in the posture snapshot.",
    },
  ],
  oauth_consent: [
    {
      key: "client_ids",
      label: "Client IDs",
      type: "list",
      description: "OAuth application client IDs to filter consent grant audit events.",
    },
    {
      key: "scope_contains",
      label: "Scope contains",
      type: "list",
      description: "Substring matches against OAuth scopes granted (e.g. Mail.Read or Directory.Read.All).",
    },
  ],
  project: [
    {
      key: "project_ids",
      label: "Project IDs",
      type: "list",
      description: "GCP project IDs to include in organization or folder-scoped collection.",
    },
    {
      key: "folder_id",
      label: "Folder ID",
      type: "string",
      description: "GCP folder ID to enumerate projects under when collecting at folder scope.",
    },
    {
      key: "organization_id",
      label: "Organization ID",
      type: "string",
      description: "GCP organization ID for org-wide project enumeration and IAM collection.",
    },
  ],
  rbac: [
    {
      key: "principal_ids",
      label: "Principal IDs",
      type: "list",
      description: "Azure AD object IDs of users, groups, or service principals to filter RBAC assignment collection.",
    },
    {
      key: "role_names",
      label: "Role names",
      type: "list",
      description: "Azure built-in or custom role definition names to scope assignment collection.",
    },
  ],
  resource_graph: [
    {
      key: "query",
      label: "Custom KQL query",
      type: "string",
      description:
        "Optional Azure Resource Graph KQL query that overrides the collector default. Use to narrow resources returned by the graph collector.",
      docUrl: AZURE_RESOURCE_GRAPH,
    },
  ],
  rds: [
    {
      key: "db_instance_ids",
      label: "DB instance IDs",
      type: "list",
      description: "RDS DB instance identifiers whose CloudWatch-exported engine logs should be collected.",
    },
    {
      key: "db_instance_arns",
      label: "DB instance ARNs",
      type: "list",
      description: "Full RDS DB instance ARNs to scope log export collection.",
    },
    {
      key: "log_types",
      label: "Log types",
      type: "list",
      description: "Exported log types to collect (e.g. error, general, slowquery, audit, postgresql).",
    },
    {
      key: "log_group_names",
      label: "Log group names",
      type: "list",
      description: "CloudWatch Logs group names (/aws/rds/instance/<id>/<type>) to collect from directly.",
    },
  ],
  route53_resolver: [
    {
      key: "query_log_config_ids",
      label: "Query log config IDs",
      type: "list",
      description: "Route 53 Resolver query logging configuration IDs.",
    },
    {
      key: "vpc_ids",
      label: "VPC IDs",
      type: "list",
      description: "VPC IDs associated with Resolver query logging to filter collected DNS queries.",
    },
  ],
  s3: [
    {
      key: "bucket_names",
      label: "Bucket names",
      type: "list",
      description: "S3 bucket names to collect configuration, policy, and inventory artifacts from.",
    },
    {
      key: "name_prefix",
      label: "Name prefix",
      type: "list",
      description: "Prefix filters on bucket names — only buckets whose names start with the given prefix are included.",
    },
  ],
  s3_access: [
    {
      key: "source_bucket_names",
      label: "Source bucket names",
      type: "list",
      description: "S3 buckets where server access logs originate (the bucket being accessed).",
    },
    {
      key: "target_bucket_names",
      label: "Target bucket names",
      type: "list",
      description: "S3 buckets that store delivered access log objects.",
    },
    {
      key: "object_key_prefix",
      label: "Object key prefix",
      type: "list",
      description: "S3 key prefix under the log delivery bucket where access log objects are stored.",
    },
  ],
  scc_findings: [
    {
      key: "severity",
      label: "Severity",
      type: "list",
      description: "Security Command Center finding severity levels to filter on (e.g. CRITICAL, HIGH, MEDIUM).",
    },
    {
      key: "state",
      label: "State",
      type: "list",
      description: "Finding state such as ACTIVE or INACTIVE.",
    },
    {
      key: "project_ids",
      label: "Project IDs",
      type: "list",
      description: "GCP project IDs to scope SCC finding collection.",
    },
  ],
  secrets: [
    {
      key: "secret_names",
      label: "Secret names",
      type: "list",
      description: "Secrets Manager secret names to collect metadata from (not secret values).",
    },
    {
      key: "secret_arns",
      label: "Secret ARNs",
      type: "list",
      description: "Full Secrets Manager secret ARNs to scope collection.",
    },
  ],
  securityhub: [
    {
      key: "severity_label",
      label: "Severity labels",
      type: "list",
      description: "Security Hub finding severity labels such as CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL.",
    },
    {
      key: "product_arns",
      label: "Product ARNs",
      type: "list",
      description: "Security Hub product ARNs to filter findings by originating integrated service.",
    },
    {
      key: "resource_arns",
      label: "Resource ARNs",
      type: "list",
      description: "AWS resource ARNs referenced in Security Hub findings.",
    },
    {
      key: "finding_types",
      label: "Finding types",
      type: "list",
      description: "Security Hub finding type identifiers (e.g. TTPs/Initial Access/...) to filter on.",
    },
  ],
  storage_access: [
    {
      key: "bucket_names",
      label: "Bucket names",
      type: "list",
      description: "GCS bucket names to filter access and usage logs.",
    },
    {
      key: "principal_email",
      label: "Principal email",
      type: "list",
      description: "Email or service account of principals recorded in storage access logs.",
    },
    {
      key: "http_status",
      label: "HTTP status",
      type: "string",
      description: "HTTP status code to filter storage access log entries (e.g. 403 for authorization failures).",
      placeholder: "403",
    },
  ],
  bigquery_audit: [
    {
      key: "dataset_ids",
      label: "Dataset IDs",
      type: "list",
      description: "BigQuery dataset IDs to scope data access audit logs.",
    },
    {
      key: "table_ids",
      label: "Table IDs",
      type: "list",
      description: "BigQuery table IDs to scope data access audit logs.",
    },
    {
      key: "principal_email",
      label: "Principal email",
      type: "list",
      description: "Email or service account that performed BigQuery data access operations.",
    },
  ],
  cloud_sql: [
    {
      key: "instance_names",
      label: "Instance names",
      type: "list",
      description: "Cloud SQL instance names (database_id label) to scope query and connection logs.",
    },
    {
      key: "regions",
      label: "Regions",
      type: "list",
      description: "GCP regions to scope Cloud SQL log collection.",
    },
    {
      key: "search_text",
      label: "Search text",
      type: "string",
      description: "Free-text search across Cloud SQL log message payloads (IOC strings, SQL fragments).",
    },
  ],
  secret_manager: [
    {
      key: "secret_names",
      label: "Secret names",
      type: "list",
      description: "Secret Manager secret IDs to scope data access audit logs.",
    },
    {
      key: "principal_email",
      label: "Principal email",
      type: "list",
      description: "Email or service account that accessed Secret Manager secrets.",
    },
  ],
  unified_audit: [
    {
      key: "content_types",
      label: "Content types",
      type: "list",
      description: "Microsoft 365 Unified Audit Log content types / workloads to include (e.g. Exchange, SharePoint, AzureActiveDirectory).",
    },
    {
      key: "users",
      label: "Users",
      type: "list",
      description: "User principal names or IDs to filter Unified Audit Log records.",
    },
    {
      key: "operations",
      label: "Operations",
      type: "list",
      description: "Audit operation names to filter on (e.g. FileDownloaded, MailItemsAccessed).",
    },
  ],
  unified_audit_search: [
    {
      key: "users",
      label: "Users",
      type: "list",
      description: "User principal names or IDs for targeted Unified Audit Log search.",
    },
    {
      key: "operations",
      label: "Operations",
      type: "list",
      description: "Audit operation names to include in search results.",
    },
    {
      key: "record_types",
      label: "Record types",
      type: "list",
      description: "Unified Audit Log record type values to filter search results.",
    },
    {
      key: "ip_addresses",
      label: "IP addresses",
      type: "list",
      description: "Client IP addresses recorded in audit records for compromise or exfiltration investigations.",
    },
  ],
  vm_logs: [
    {
      key: "instance_ids",
      label: "Instance IDs",
      type: "list",
      description: "Compute Engine instance IDs to collect serial port, OS login, or guest OS logs from.",
    },
    {
      key: "zones",
      label: "Zones",
      type: "list",
      description: "GCP zones to scope VM log collection (e.g. us-central1-a).",
    },
    {
      key: "search_text",
      label: "Search text",
      type: "string",
      description: "Free-text substring to search VM logs for IOCs, hostnames, or error messages.",
    },
  ],
  vnet_flow: [
    {
      key: "flow_log_names",
      label: "Flow log names",
      type: "list",
      description: "Azure Virtual Network flow log resource names.",
    },
    {
      key: "target_resource_ids",
      label: "Target resource IDs",
      type: "list",
      description: "ARM IDs of VNets, subnets, or NICs configured for flow logging.",
    },
    {
      key: "storage_account_ids",
      label: "Storage account IDs",
      type: "list",
      description: "Storage accounts where VNet flow logs are persisted.",
    },
    {
      key: "resource_group_names",
      label: "Resource group names",
      type: "list",
      description: "Resource groups containing flow log resources to scope collection.",
    },
  ],
  vpc_flow: [
    {
      key: "subnetwork_names",
      label: "Subnetwork names",
      type: "list",
      description: "GCP VPC subnetwork names to filter VPC Flow Logs.",
    },
    {
      key: "regions",
      label: "Regions",
      type: "list",
      description: "GCP regions to scope VPC Flow Log collection.",
    },
    {
      key: "zones",
      label: "Zones",
      type: "list",
      description: "GCP zones to further narrow flow log sources.",
    },
    {
      key: "dest_ip",
      label: "Destination IP",
      type: "list",
      description: "Destination IP addresses to filter flow log records (useful for C2 or lateral movement hunts).",
    },
    {
      key: "action",
      label: "Action",
      type: "list",
      description: "Filter flow records by disposition: ALLOW or DENY.",
      docUrl: GCP_VPC_FLOW,
    },
  ],
  waf: [
    {
      key: "web_acl_arns",
      label: "Web ACL ARNs",
      type: "list",
      description: "AWS WAF web ACL ARNs to collect rule matches and sampled requests from.",
    },
    {
      key: "web_acl_names",
      label: "Web ACL names",
      type: "list",
      description: "WAF web ACL names as shown in the AWS WAF console.",
    },
  ],
};

export function collectorParamSchema(collector: string): ParamFieldDef[] {
  return COLLECTOR_PARAM_SCHEMAS[collector] ?? [];
}

export function hasCollectorParams(collector: string): boolean {
  return collectorParamSchema(collector).length > 0;
}
