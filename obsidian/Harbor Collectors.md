<style>
/* Widen tables in this note */
.markdown-preview-view.is-readable-line-width .markdown-preview-sizer,
.markdown-source-view.mod-cm6.is-readable-line-width .cm-contentContainer {
  max-width: 100% !important;
}

.harbor-collectors table {
  width: 100%;
  max-width: 100%;
  table-layout: fixed;
}

.harbor-collectors th,
.harbor-collectors td {
  vertical-align: top;
  word-wrap: break-word;
  overflow-wrap: anywhere;
  padding: 10px 12px;
}

.harbor-collectors th:nth-child(1),
.harbor-collectors td:nth-child(1) {
  width: 13%;
}

.harbor-collectors th:nth-child(2),
.harbor-collectors td:nth-child(2) {
  width: 27%;
}

.harbor-collectors th:nth-child(3),
.harbor-collectors td:nth-child(3) {
  width: 27%;
}

.harbor-collectors th:nth-child(4),
.harbor-collectors td:nth-child(4) {
  width: 33%;
}

.harbor-cli table {
  width: 100%;
  max-width: 100%;
  table-layout: fixed;
}

.harbor-cli th:nth-child(1),
.harbor-cli td:nth-child(1) {
  width: 35%;
}

.harbor-cli th:nth-child(2),
.harbor-cli td:nth-child(2) {
  width: 65%;
}
</style>

All collectors currently implemented in Harbor (`harbor-collect aws`). **Tier 1** runs in the baseline profile; **Tier 2** collectors are opt-in via extended profiles.

**GUI panel names** match the Harbor Evidence Viewer sidebar unless noted.

<div class="harbor-collectors">

## Identity & Access

| Collector | What it does & where it collects from | Why it matters for incident responders | Where it shows in the GUI |
|-----------|---------------------------------------|----------------------------------------|---------------------------|
| <span style="color:#7DD3FC">Account Context</span> | Captures account ID, alias, AWS Organization membership, enabled regions, and the operator identity (ARN) that ran the collection. Pulled from **STS**, **IAM**, **Organizations**, and **EC2 DescribeRegions** APIs — global/account scope. | Gives every other artifact context: which account, which org, who collected, and what regions were in scope. Essential for chain of custody and scoping the investigation. | **Cases** list (account ID per case) · **Top bar** (Account ID on every case view) · **Collection Coverage** (collector status) |
| <span style="color:#7DD3FC">IAM Snapshot</span> | Point-in-time inventory of **users, roles, groups, policies, trust relationships, access keys**, and the **IAM credential report** (password/key age, last use, MFA). Collected from the **IAM** API across the account (`GetAccountAuthorizationDetails` with per-principal fallback). | Answers "who could do what" at collection time. Surfaces privilege-escalation paths, backdoor roles, risky trust policies, stale keys, and missing MFA — the backbone of the Identity panel. | **Identity & Access** (users table, roles list, stat cards) · collector chips on panel headers |
| <span style="color:#7DD3FC">STS Activity</span> | Pulls **AssumeRole**, **AssumeRoleWithSAML**, and **AssumeRoleWithWebIdentity** events from **CloudTrail LookupEvents** in every in-scope region (~90-day lookback). STS has no separate event API — CloudTrail is the authoritative source. | Shows how an attacker moved through identities: console login → role chaining → federated access → temporary credentials. Powers the role-assumption graph in the console. | **CloudTrail Timeline** (AssumeRole events merged with CloudTrail source) · **Identity & Access** (role-assumption graph API — graph component scaffolded) |
| <span style="color:#7DD3FC">KMS</span> | Inventories **KMS keys** per region with **key policies** and **grants**. Collected from the **KMS** API (`ListKeys`, `DescribeKey`, `GetKeyPolicy`, `ListGrants`). Key *usage* events come from CloudTrail separately. | Key-policy changes and broad grants enable decryption of sensitive data and persistence. Responders need to know which keys exist and whether policies were widened during the incident. | **Identity & Access** (KMS keys stat card + inventory section) · **Collection Coverage** |
| <span style="color:#7DD3FC">Secrets Manager</span> | Collects **secret metadata only** — names, rotation config, resource policies, last-changed/last-accessed timestamps. **Never pulls secret values.** Collected from **Secrets Manager** per region. Access/change events are in CloudTrail. | Shows what credentials and API keys were reachable. Attackers target secrets for lateral movement; knowing what existed (without exfiltrating values) guides pivoting and containment. | **Identity & Access** (Secrets stat card + inventory section) · **Collection Coverage** |

## Control Plane

| Collector | What it does & where it collects from | Why it matters for incident responders | Where it shows in the GUI |
|-----------|---------------------------------------|----------------------------------------|---------------------------|
| <span style="color:#86EFAC">CloudTrail</span> | The control-plane backbone. Collects **trail configuration** (selectors, log validation, S3 delivery) from the **CloudTrail** API; **management** and **insight** events via **LookupEvents**; **data** and **network-activity** events from the trail's **S3 log bucket** when enabled. All in-scope regions. | Usually the primary investigation timeline: who did what, when, from which IP, against which resource. Without CloudTrail, cloud IR is largely blind. | **CloudTrail Timeline** (primary table + filters + event drawer) · **Timeline** route (multi-source brushable timeline) · **Context drawer** on any event row click |
| <span style="color:#86EFAC">AWS Config</span> | Captures **configuration recorder** state, **delivery channels**, and **compliance-by-rule** status from the **AWS Config** API per region. Records whether change history was being captured (recorder on/off is itself evidence). | Answers "what changed" and "what was misconfigured." A disabled recorder can indicate defense evasion; failing compliance rules highlight blast-radius and risky resources. | **Security Findings** (compliance findings when ingested) · **Collection Coverage** (recorder state & gaps) |

## Network

| Collector | What it does & where it collects from | Why it matters for incident responders | Where it shows in the GUI |
|-----------|---------------------------------------|----------------------------------------|---------------------------|
| <span style="color:#5EEAD4">VPC Flow Logs</span> | Establishes **flow log configuration** (which VPCs/subnets log, destination: CloudWatch vs S3) via **EC2 DescribeFlowLogs**, then pulls **recent flow records** from **CloudWatch Logs** when that is the destination. Per region. | The exfiltration lens: top talkers, rejected flows, egress to public IPs, lateral movement inside the VPC. A missing flow log config is documented as a gap — itself evidence. | **Network Activity** (flow stats, top destinations by volume, rejected flows table) · collector chips on **Network Activity** header |
| <span style="color:#5EEAD4">AWS WAF</span> | Collects **WAFv2 Web ACL** configurations, **logging setup**, and **sampled requests** from the **WAFv2** API. Queries both **regional** scopes (per region) and **CLOUDFRONT** (global, via us-east-1). | Shows web-layer attacks at the edge and what was blocked vs allowed. Disabled WAF logging is a common gap that limits HTTP-level visibility. | **Collection Coverage** (status & gaps) · collector chips on **Network Activity** header — *no dedicated WAF table view yet* |

## Threat Detection

| Collector | What it does & where it collects from | Why it matters for incident responders | Where it shows in the GUI |
|-----------|---------------------------------------|----------------------------------------|---------------------------|
| <span style="color:#FCD34D">GuardDuty</span> | Pulls **findings**, **detector configuration**, and **suppression filters** from the **GuardDuty** API in every in-scope region. Whether GuardDuty is enabled at all is recorded. | Often the first automated signal of compromise: recon, credential abuse, crypto mining, exfiltration behaviors. Suppression filters are collected because they can hide attacker activity. | **Security Findings** (findings table, Source filter, event drawer) · collector chips on **Security Findings** header |
| <span style="color:#FCD34D">Security Hub</span> | Collects **hub settings**, **enabled standards**, and **ASFF findings** from the **Security Hub** API per region. Aggregates GuardDuty, Config, Inspector, Macie, and partner products. | One deduplicated feed across services — faster triage in the Security Findings panel. Shows which compliance standards were active during the incident. | **Security Findings** (findings table + Source filter as "Security Hub") · **Collection Coverage** |
| <span style="color:#FCD34D">Macie</span> | Collects **Macie session status** and **sensitive-data / policy findings** from the **Macie2** API per region. Preserves full detail when Macie runs standalone or findings are not forwarded to Security Hub. | Points responders at exposed or mishandled data in S3 — critical for data-theft and compliance cases. | **Security Findings** (findings table + Source filter as "Macie") · **Collection Coverage** |
| <span style="color:#FCD34D">Detective</span> | Lists **Detective graph membership** and **open investigations** from the **Detective** API per region. Detective does not expose GuardDuty-style findings — investigations are the IR-ready signal. | Shows whether the account was already under structured investigation and which graphs existed. Useful context when coordinating with a customer SOC that uses Detective. | **Security Findings** (when normalized as findings) · **Collection Coverage** (graph & investigation inventory) |

## Workloads & Storage

| Collector | What it does & where it collects from | Why it matters for incident responders | Where it shows in the GUI |
|-----------|---------------------------------------|----------------------------------------|---------------------------|
| <span style="color:#C4B5FD">EC2 / EBS</span> | **Metadata-only** inventory: instances, volumes, ENIs, security groups, AMIs, launch templates, plus the **EBS snapshot trail** (creation, cross-account sharing, cross-region copy). Collected from **EC2** APIs per region. Includes user-data where readable. Does **not** collect disk images. | User-data and security groups are common persistence and exfil paths. Shared/public snapshots are a classic data-theft technique — the Resources panel highlights these. | **Resources** → Compute & storage tab (instances, snapshots, shared-snapshot highlighting) · **Collection Coverage** — *route exists at `/resources`; not yet in the sidebar* |
| <span style="color:#C4B5FD">S3 Surface</span> | Bucket **inventory** with **public access**, **ACLs**, **bucket policies**, **access logging**, **Object Lock**, and **public-access-block** state. Collected from the **S3** API (global bucket list, per-bucket settings). Object-access events come from CloudTrail data events separately. | S3 is the most common cloud exfil target. Surfaces public buckets, permissive policies, and logging gaps before you even open the timeline. | **Resources** → S3 buckets tab (exposure, policies, logging state) · **Collection Coverage** — *route exists at `/resources`; not yet in the sidebar* |
| <span style="color:#C4B5FD">Lambda</span> | **Function inventory** with **resource policies** and **redacted environment configuration** (secret-looking values redacted; keys kept). Collected from the **Lambda** API per region. | Lambda is a common persistence and exfil vector — attacker-created functions, over-broad invoke policies, secrets in env vars. Inventory tells you what existed without pulling live secrets. | **Collection Coverage** only — *no dedicated Lambda panel yet*; inventory available via API (`/inventory/lambda`) |

</div>

---

## GUI panel quick reference

| Panel (sidebar) | Collectors that feed it |
|-----------------|------------------------|
| **Overview** | account, cloudtrail, iam, sts, vpc_flow, guardduty, waf (+ roll-up of all ingested events) |
| **CloudTrail Timeline** | cloudtrail, sts |
| **Security Findings** | guardduty, securityhub, macie, detective, config |
| **Identity & Access** | iam, kms, secrets (+ sts for role-assumption graph) |
| **Network Activity** | vpc_flow, waf |
| **Collection Coverage** | *all collectors* — collected / partial / missing / denied |
| **Resources** *(route only)* | ec2, s3 |

**Also surfaces everywhere:** case **Top bar** (account, time window) · **Context drawer** (raw event on row click) · **Pivot menu** (jump to another panel with filters pre-applied) · **Report** (case summary export).

---

## Baseline profile (`--profile baseline`)

These collectors run by default on any unknown incident:

- <span style="color:#7DD3FC">account</span>
- <span style="color:#86EFAC">cloudtrail</span>
- <span style="color:#5EEAD4">vpc_flow</span>
- <span style="color:#FCD34D">guardduty</span>
- <span style="color:#5EEAD4">waf</span>
- <span style="color:#7DD3FC">iam</span>
- <span style="color:#7DD3FC">sts</span>

---

## CLI collector names

<div class="harbor-cli">

| Name in this note | Collector flag |
|-------------------|----------------|
| <span style="color:#7DD3FC">Account Context</span> | `account` |
| <span style="color:#7DD3FC">IAM Snapshot</span> | `iam` |
| <span style="color:#7DD3FC">STS Activity</span> | `sts` |
| <span style="color:#7DD3FC">KMS</span> | `kms` |
| <span style="color:#7DD3FC">Secrets Manager</span> | `secrets` |
| <span style="color:#86EFAC">CloudTrail</span> | `cloudtrail` |
| <span style="color:#86EFAC">AWS Config</span> | `config` |
| <span style="color:#5EEAD4">VPC Flow Logs</span> | `vpc_flow` |
| <span style="color:#5EEAD4">AWS WAF</span> | `waf` |
| <span style="color:#FCD34D">GuardDuty</span> | `guardduty` |
| <span style="color:#FCD34D">Security Hub</span> | `securityhub` |
| <span style="color:#FCD34D">Macie</span> | `macie` |
| <span style="color:#FCD34D">Detective</span> | `detective` |
| <span style="color:#C4B5FD">EC2 / EBS</span> | `ec2` |
| <span style="color:#C4B5FD">S3 Surface</span> | `s3` |
| <span style="color:#C4B5FD">Lambda</span> | `lambda` |

</div>

---

## Planned (not yet implemented)

Azure and GCP collectors are catalogued in Harbor for future phases. They are **not** registered in the collector yet.

### Azure (planned)

| Collector | What it does & where it collects from | Why it matters for incident responders | Where it will show in the GUI |
|-----------|---------------------------------------|----------------------------------------|-------------------------------|
| <span style="color:#94A3B8">Entra ID Sign-ins</span> | Microsoft Entra ID sign-in logs. | Authentication timeline for hybrid / Azure AD environments. | **Identity & Access** · **CloudTrail Timeline** equivalent |
| <span style="color:#94A3B8">Entra ID Audit</span> | Directory change audit logs. | Tracks identity and configuration changes during the incident. | **Identity & Access** |
| <span style="color:#94A3B8">Azure RBAC</span> | Role assignments and definitions. | Maps who had access to what in the subscription. | **Identity & Access** |
| <span style="color:#94A3B8">Activity Log</span> | Subscription control-plane operations. | Azure equivalent of CloudTrail management events. | **CloudTrail Timeline** equivalent |
| <span style="color:#94A3B8">NSG Flow Logs</span> | Network security group flow logs. | Network visibility for lateral movement and exfil. | **Network Activity** |
| <span style="color:#94A3B8">Defender for Cloud</span> | Microsoft Defender alerts. | Native threat detections aggregated for triage. | **Security Findings** |

### GCP (planned)

| Collector | What it does & where it collects from | Why it matters for incident responders | Where it will show in the GUI |
|-----------|---------------------------------------|----------------------------------------|-------------------------------|
| <span style="color:#94A3B8">IAM Policy</span> | Policy bindings and service accounts. | Who could access which resources. | **Identity & Access** |
| <span style="color:#94A3B8">Login Events</span> | Workspace / Cloud Identity logins. | Authentication evidence for human access. | **Identity & Access** |
| <span style="color:#94A3B8">Audit: Admin Activity</span> | Cloud Audit Logs — admin activity. | Control-plane change timeline. | **CloudTrail Timeline** equivalent |
| <span style="color:#94A3B8">Audit: Data Access</span> | Cloud Audit Logs — data access. | Who read or wrote sensitive data. | **CloudTrail Timeline** · **Security Findings** |
| <span style="color:#94A3B8">VPC Flow Logs</span> | VPC flow logs. | Network traffic evidence inside GCP VPCs. | **Network Activity** |
| <span style="color:#94A3B8">Security Command Center</span> | SCC findings. | Centralized threat and misconfiguration findings. | **Security Findings** |

---

## Related notes

- [[Ventra Collectors]]
- [[Control Plane And Cloud Native Logs]]
- [[Network And Edge Logs]]
- [[EC2 & EBS Logs]]
- [[Questions the tool should ask before collecting]]
