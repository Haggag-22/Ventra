## The end-to-end story (30 seconds)

Client CloudShell → sealed evidence package → ingester → analyst console

(collect) (.tar.zst + manifest) (normalize) (investigate)

Three tiers, one contract:

|Tier|Where it runs|What it does|
|---|---|---|
|Collector|Client AWS CloudShell|Read-only acquisition → sealed package|
|Ingester|IR workstation|Verify signatures → parse → normalize → DuckDB/Parquet|
|Console|IR workstation|Case-scoped investigation GUI (no outbound calls)|

Forensic principles baked in: read-only IAM, SHA-256 on every artifact, signed manifest, chain of custody, and gaps are evidence (a disabled log source is recorded, not hidden).

---

## Part 1 — The Collectors (22 AWS sources, one command)

Every `ventra collect aws` run executes all registered collectors in order. There are no profiles to pick — the manifest and console show what came back and what didn't.

### Control plane & audit

|Collector|What it pulls|
|---|---|
|account|Account ID, alias, org, regions, operator context|
|cloudtrail|Trail config; management, data, insight, and network-activity events from S3 logs (LookupEvents fallback); S3 log integrity validation (`validate-logs`)|
|config|AWS Config recorder state and compliance findings|
|log_posture|_Discovery only_ — checks whether API Gateway, Lambda, OpenSearch, RDS, DynamoDB Streams, and Network Firewall logging is enabled and where it ships (even when Ventra can't pull those logs yet)|

### Identity & secrets

|Collector|What it pulls|
|---|---|
|iam|Users, roles, groups, policies, access keys, credential report|
|kms|Key inventory, policies, grants|
|secrets|Secrets Manager metadata (never values), rotation, resource policies|

### Network & edge

|Collector|What it pulls|
|---|---|
|vpc_flow|VPC Flow Log config + flow records (CloudWatch and/or S3)|
|elb_alb|ALB/ELB access logs from S3 + per-LB logging posture|
|cloudfront|CloudFront standard access logs from S3 + distribution logging posture|
|route53_resolver|DNS query logs from S3 or CloudWatch|
|waf|WAFv2 Web ACL configs, logging config, sampled requests|

### Workloads & data plane

|Collector|What it pulls|
|---|---|
|ec2|EC2/EBS inventory; snapshot share/copy evidence (metadata only)|
|s3|Bucket inventory, public exposure, policies, logging, Object Lock|
|s3_access|S3 server access logs from logging target buckets|
|lambda|Function inventory, resource policies, redacted env config|
|eks_audit|EKS API-server audit logs from CloudWatch + cluster audit-logging posture|

### Detections & findings

|Collector|What it pulls|
|---|---|
|guardduty|GuardDuty findings, detector config, suppression filters|
|securityhub|Security Hub findings (ASFF), enabled standards|
|inspector2|Vulnerability / network-reachability findings|
|macie|Sensitive-data and policy findings|
|detective|Detective graph config and open investigations|

Client install: one line in CloudShell → `ventra collect aws --case … --since … --out ~/ventra-evidence`. Package is sealed, signed, and SHA-256 printed for handoff.

---

## Part 2 — The Analyst Console

#### 1. CloudTrail Timeline

Purpose: Control-plane and API activity — who did what, when, from where.

---

#### 2. Security Findings

Purpose: Normalize threat detections from GuardDuty, Security Hub, Inspector, Macie, and Detective into one view.

---

#### 3. Identity & Access

Purpose: IAM posture at time of collection — privilege escalation and credential risk.

---

#### 4. Network Activity

Purpose: VPC Flow Logs — exfiltration volume and lateral movement / scanning.

Shows:

- Totals: flows, accepted, rejected, public egress bytes, external destinations
- Egress to public IPs — rank-ordered exfil candidates (bytes, flows, port diversity)
- Destination ports — volume bars with accepted vs rejected share; risky ports (RDP, SSH, Redis, etc.) flagged
- Top talkers — highest byte-volume internal sources
- Rejected flows — top source→dest→port blocked attempts (recon / policy denials)
- Protocols — TCP/UDP/ICMP mix
- Pivot any IP into timeline correlation

---

#### 5. Web & DNS

Purpose: Layer-7 activity — what was requested, by whom, with what result.

Fed by: ELB/ALB access logs, CloudFront, WAF sampled requests, Route53 Resolver query logs.

Shows:

- Request totals by source (ELB, CloudFront, WAF, DNS)
- HTTP status mix (2xx / 3xx / 4xx / 5xx)
- Top paths/URLs, top client IPs, top DNS domains
- Suspicious domain heuristics (long labels, deep subdomains, high digit density → possible DGA/tunneling)
- WAF blocked requests by client IP and country

---

#### 6. Data Access

Purpose: Object-level S3 access — who read or wrote which object, from where.

Fed by: S3 server access logs + CloudTrail S3 data events.

Shows:

- Event totals, bytes transferred, unique objects/principals/IPs
- Operation mix — delete / write / read / list (color-coded by IR weight)
- Top accessed objects, top principals, top source IPs
- Scope filter for pivoted entity
- Empty state explains manifest gaps when logging wasn't configured

---




---

### Cross-cutting analyst features

| Feature              | What it does                                                                        |
| -------------------- | ----------------------------------------------------------------------------------- |
| Pivot / Entity links | Click a user, IP, or resource → sets case scope; other panels filter to that entity |
| Context drawer       | Full event detail, outcome/severity badges, raw JSON, pin to report                 |
| Command palette (⌘K) | Jump to panels, search facets, quick navigation                                     |
| Keyboard shortcuts   | `g c` → CloudTrail, `g f` → Findings, `g i` → Identity, etc.                        |
| Scope bar            | Visible when a pivot is active; clear to return to full case                        |
| Read-only badge      | Console never mutates evidence or calls outbound APIs                               |

---

## Part 3 — What to say about gaps & roadmap (honest framing)

What's strong today:

- Full AWS Tier-1 collector set (22 sources)
- End-to-end: CloudShell → sealed package → ingest → multi-panel investigation
- Gaps and logging posture are first-class (not silent failures)
- CloudTrail S3 integrity validation
- Unified event model across CloudTrail, findings, flow logs, web logs, and S3 access

What's not built yet (good to mention if asked):

- File Browser — sidebar shows "soon"
- Azure / GCP collectors — catalog scaffolded, not implemented
- Some cheat-sheet sources are detected only (log_posture), not collected (API Gateway, Lambda logs, RDS exports, etc.)
- Collector caps (200k records, 2k S3 objects) for CloudShell safety — large cases may need EC2 or narrower windows