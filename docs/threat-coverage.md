# Threat coverage — MITRE ATT&CK for Cloud (IaaS)

Which sources Ventra collects answer which questions. This drives both the collection
packs and the console **Logs Coverage** panel's gap callouts (for example "you'd want X
enabled next time").

Ventra's collection scope deliberately targets Shawn's four questions:

1. **Who authenticated where** → CloudTrail (console logins, AssumeRole), IAM, STS;
   Azure Entra sign-in / audit; GCP login events and Cloud Audit Admin.
2. **What did they do once authenticated** → CloudTrail management events, Config history;
   Azure Activity Log; GCP Cloud Audit Admin / System.
3. **Were resources changed or accessed** → CloudTrail data events, Config, S3 surface,
   EC2/EBS/Lambda inventory + change-during-window; Azure storage / Key Vault access;
   GCP Data Access audit, GCS / BigQuery / Secret Manager collectors.
4. **Data exfiltration** → VPC Flow Logs, DNS resolver logs, S3 access, CloudFront, EBS
   snapshot share/copy history; Azure VNet/NSG/firewall flow and Front Door; GCP VPC flow,
   firewall, NAT, load balancer / CDN.

## Coverage matrix

| ATT&CK Tactic | Representative techniques | Primary Ventra sources |
|---------------|---------------------------|------------------------|
| Initial Access | Valid Accounts (T1078.004) | CloudTrail console logins, STS, IAM credential report; Entra sign-in; GCP login events |
| Execution | Cloud Admin Command, Serverless | CloudTrail, Lambda inventory + lambda_logs, Cloud Functions |
| Persistence | Additional Cloud Credentials (T1098.001), Additional Cloud Roles | CloudTrail (CreateAccessKey/CreateUser via reads of resulting state), IAM / Entra / GCP IAM snapshot, OAuth consent |
| Privilege Escalation | Additional Cloud Roles (T1098.003) | IAM / RBAC snapshot, CloudTrail / Activity Log / Cloud Audit |
| Defense Evasion | Impair Defenses: Disable Cloud Logs (T1562.008) | CloudTrail config + digest, GuardDuty detector state, Config recorder state, log_posture / logging_posture / diag_posture |
| Credential Access | Cloud Instance Metadata API, Secrets (T1552.005/.001) | CloudTrail, Secrets Manager / Secret Manager / Key Vault access events |
| Discovery | Cloud Service Discovery (T1526), Account Discovery (T1087.004) | CloudTrail (Describe/List bursts); Resource Graph / GCE inventory |
| Lateral Movement | Use Alternate Auth Material (T1550.001) | STS AssumeRole chains, CloudTrail; Entra / GCP IAM |
| Collection | Data from Cloud Storage (T1530) | S3 access logs, CloudTrail data events; Azure/GCS storage access |
| Exfiltration | Transfer to Cloud Account (T1537) | EBS snapshot share/copy history, VPC Flow, DNS, CloudFront / Front Door / CDN |
| Impact | Data Destruction, Resource Hijacking (T1496) | CloudTrail, GuardDuty / Defender / SCC findings, Config |

## Gaps Ventra surfaces

When a source needed to answer a tactic is disabled, **Logs Coverage** calls it out from
the manifest — e.g. "VPC Flow Logs not enabled → exfiltration volume cannot be quantified
for this window." Individual investigation panels show the same coverage chips for the
collectors that feed them (`panel-collectors.ts`), so analysts see blind spots next to the
evidence they are reading.
