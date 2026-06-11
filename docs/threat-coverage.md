# Threat coverage — MITRE ATT&CK for Cloud (IaaS)

Which sources Harbor collects answer which questions. This drives both the collection
profiles and the console's "you'd want X enabled next time" recommendations.

Harbor's collection scope deliberately targets Shawn's four questions:

1. **Who authenticated where** → CloudTrail (console logins, AssumeRole), IAM, STS.
2. **What did they do once authenticated** → CloudTrail management events, Config history.
3. **Were resources changed or accessed** → CloudTrail data events, Config, S3 surface,
   EC2/EBS/Lambda inventory + change-during-window.
4. **Data exfiltration** → VPC Flow Logs, DNS resolver logs, S3 access, CloudFront, EBS
   snapshot share/copy history, Transit Gateway flow logs.

## Coverage matrix

| ATT&CK Tactic | Representative techniques | Primary Harbor sources |
|---------------|---------------------------|------------------------|
| Initial Access | Valid Accounts (T1078.004) | CloudTrail console logins, STS, IAM credential report |
| Execution | Cloud Admin Command, Serverless | CloudTrail, Lambda inventory, SSM |
| Persistence | Additional Cloud Credentials (T1098.001), Additional Cloud Roles | CloudTrail (CreateAccessKey/CreateUser via reads of resulting state), IAM snapshot |
| Privilege Escalation | Additional Cloud Roles (T1098.003) | IAM snapshot, role-assumption graph, CloudTrail |
| Defense Evasion | Impair Defenses: Disable Cloud Logs (T1562.008) | CloudTrail config + digest, GuardDuty detector state, Config recorder state |
| Credential Access | Cloud Instance Metadata API, Secrets (T1552.005/.001) | CloudTrail, Secrets Manager, SSM Parameter Store access events |
| Discovery | Cloud Service Discovery (T1526), Account Discovery (T1087.004) | CloudTrail (Describe/List bursts) |
| Lateral Movement | Use Alternate Auth Material (T1550.001) | STS AssumeRole chains, CloudTrail |
| Collection | Data from Cloud Storage (T1530) | S3 access logs, CloudTrail data events |
| Exfiltration | Transfer to Cloud Account (T1537) | EBS snapshot share/copy history, VPC Flow, DNS, CloudFront |
| Impact | Data Destruction, Resource Hijacking (T1496) | CloudTrail, GuardDuty findings, Config |

## Gaps Harbor surfaces

When a source needed to answer a tactic is disabled, the console's **Collection** panel calls
it out explicitly — e.g. "VPC Flow Logs not enabled → exfiltration volume cannot be
quantified for this window." The IOCs & Hunts panel renders the same matrix against the
*actually loaded* sources so analysts see their blind spots at a glance.
