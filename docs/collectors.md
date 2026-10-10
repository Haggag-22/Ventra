# Collectors

Every log source and snapshot Ventra can collect, per cloud. In the console you pick these in
**Configuration → Acquire** when you build a Collection Kit. Each one is defined in
[`artifacts/`](../artifacts/) (YAML) and implemented under `collector/engine/api/`.

Ventra also ships a curated **baseline IR pack** per cloud in
[`artifacts/packs/`](../artifacts/packs/).

Read-only permissions for each cloud are in [`docs/iam-policies/`](iam-policies/). Review them
with the account owner before any engagement.

## AWS log sources

| Source | Description |
|--------|-------------|
| **CloudTrail** | Management, data, insight, and network activity events; trail config; S3 log integrity validation |
| **AWS Config** | Recorder state and compliance findings |
| **VPC Flow Logs** | Flow log configuration and flow records from CloudWatch or S3 |
| **WAF** | WAFv2 Web ACL configs, logging configuration, sampled requests |
| **ELB/ALB Access Logs** | Access logs from S3 delivery buckets and per LB logging posture |
| **CloudFront Access Logs** | Standard access logs from S3 and per distribution logging posture |
| **Route 53 Resolver Query Logs** | DNS query logs from S3 or CloudWatch destinations |
| **S3 Access Logs** | Server access logs from logging target buckets and per bucket posture |
| **EKS Audit Logs** | Kubernetes API server audit logs from CloudWatch and cluster posture |
| **GuardDuty** | Findings, detector config, suppression filters |
| **Security Hub** | ASFF findings and enabled standards |
| **Inspector2** | Vulnerability and network reachability findings |
| **Macie** | Sensitive data and policy findings |
| **Detective** | Graph membership and open investigations |

## AWS inventory and posture

| Source | Description |
|--------|-------------|
| **Account** | Account, organization, region, and operator context |
| **IAM** | Users, roles, groups, policies, access keys, credential report |
| **KMS** | Key inventory, key policies, and grants |
| **Secrets Manager** | Metadata (never secret values), rotation, resource policies |
| **EC2 / EBS** | Instance and volume inventory; snapshot share/copy evidence trail |
| **S3** | Bucket inventory, public exposure, policies, logging, Object Lock |
| **Lambda** | Function inventory, resource policies, redacted environment config |
| **Log posture** | Presence detection for sources without a dedicated log collector yet (OpenSearch, DynamoDB Streams, Network Firewall) |
| **CloudWatch Logs** | Events from selected log groups (by name, ARN, or prefix); prefer domain collectors when the service is known |
| **API Gateway** | REST/HTTP API stage access logs from CloudWatch (Logs Coverage; no dedicated edge panel chip yet) |
| **Lambda logs** | Function execution logs from CloudWatch Logs (Logs Coverage) |
| **RDS logs** | Engine logs exported to CloudWatch Logs (Logs Coverage; not in-DB logs) |

Review the read only IAM policy before any engagement:
[`docs/iam-policies/aws-collector-readonly.json`](iam-policies/aws-collector-readonly.json).

## Azure

Review read only permissions before any engagement:

- ARM: [`docs/iam-policies/azure-collector-readonly.json`](iam-policies/azure-collector-readonly.json)
- Microsoft Graph: [`docs/iam-policies/azure-collector-graph.json`](iam-policies/azure-collector-graph.json)

### Identity and control plane

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `subscription` | Tenant, subscription, and operator context | Resource Inventory |
| `entra_signin` | Entra ID sign in logs (P1/P2 required) | Activity Log |
| `entra_audit` | Entra ID directory audit logs | Activity Log |
| `entra_directory` | Users, groups, applications, service principals snapshot | Identity & Access |
| `rbac` | Azure RBAC role definitions and assignments | Identity & Access |
| `activity_log` | Azure Activity Log: ARM control plane operations (89d default) | Activity Log |
| `oauth_consent` | OAuth2 permission grants inventory | Activity Log |
| `defender` | Microsoft Defender for Cloud security alerts | Security Findings |
| `resource_graph` | Cross subscription ARM inventory snapshot | Resource Inventory |
| `diag_posture` | Diagnostic settings routing posture (Storage / LA / none) | Logs Coverage |

### Network and data access

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `vnet_flow` | VNet flow logs from delivery Storage account | Network Activity |
| `nsg_flow` | Legacy NSG flow logs from Storage | Network Activity |
| `azure_firewall` | Azure Firewall application/network/DNS logs (Storage diagnostics) | Network Activity |
| `app_gateway` | Application Gateway access, performance, and WAF logs | Web & DNS |
| `front_door` | Front Door / CDN access and WAF logs | Web & DNS |
| `dns` | Public/private DNS and resolver query logs | Web & DNS |
| `storage_access` | Storage account read/write/delete access logs | Data Access |
| `key_vault` | Key Vault audit events | Data Access |
| `aks_audit` | AKS kube audit logs from Storage diagnostics | Kubernetes Audit |


## GCP

GCP collectors cover Cloud Audit Logs (admin, system, data access), login events, SCC and
Cloud Monitoring findings, VPC flow / firewall / NAT and network posture, load balancer /
CDN / API Gateway / DNS / Cloud Armor, Cloud Storage / BigQuery / Cloud SQL / Secret Manager
access, GCE and Cloud Functions inventory and logs, GKE audit, IAM policy snapshot, and
logging posture. Every source can be picked individually in **Acquire**.

See [`docs/artifacts.md`](artifacts.md) for the catalog layout,
[`artifacts/packs/baseline-ir-gcp.yaml`](../artifacts/packs/baseline-ir-gcp.yaml) for the curated
IR bundle, and the console **Docs → Google Cloud Platform → Collectors** pages for per-collector
permissions and parameters (sourced from the artifact YAML).

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `project` | Project, organization, and operator context | Resource Inventory |
| `iam_policy` | IAM bindings, service accounts, key metadata, custom roles | Identity & IAM |
| `login_events` | Google Cloud console sign-in audit events | Audit Log / Identity & IAM |
| `cloud_audit_admin` | Admin Activity audit logs | Audit Log |
| `cloud_audit_system` | System Event audit logs | Audit Log |
| `cloud_audit_data` | Data Access audit logs | Audit Log / Storage Access |
| `logging_posture` | Flow logs, firewall logging, and audit sink posture | Logs Coverage |
| `vpc_flow` | VPC Flow Logs (sampled L3/L4) | VPC & Firewall |
| `firewall_logs` | VPC firewall rule hit logs | VPC & Firewall |
| `cloud_nat` | Cloud NAT translation logs | VPC & Firewall |
| `network_posture` | Firewall rules, VPC topology, packet mirroring | VPC & Firewall |
| `load_balancer` | Cloud Load Balancing Logs (HTTP(S) / TCP/UDP proxy) | Load Balancer & API Gateway |
| `cloud_cdn` | CDN cache request logs | Load Balancer & API Gateway |
| `api_gateway` | API Gateway request logs | Load Balancer & API Gateway |
| `cloud_dns` | Cloud DNS query logs | Load Balancer & API Gateway |
| `cloud_armor` | Cloud Armor policy inventory and enforced request logs | Load Balancer & API Gateway |
| `storage_access` | GCS bucket access / data-plane audit logs | Storage Access |
| `bigquery_audit` | BigQuery data access audit logs | Storage Access |
| `cloud_sql` | Cloud SQL query, connection, and error logs | Storage Access |
| `secret_manager` | Secret Manager access audit logs | Storage Access |
| `gce` | GCE instance, disk, snapshot, and NIC inventory | Resource Inventory |
| `vm_logs` | GCE VM logs via the Cloud Logging agent | Resource Inventory |
| `cloud_functions` | Cloud Functions execution and platform logs | Resource Inventory |
| `gke_audit` | GKE API-server audit logs + cluster posture | GKE Audit Logs |
| `scc_findings` | Security Command Center findings | Security Command Center |
| `cloud_monitoring` | Cloud Monitoring alert / incident notifications | Security Command Center |
## Kubernetes (self-managed / on-prem)

Kubernetes kits are **download-only**: build the kit in Acquire, download it, and run it with
`ventra run` on a control-plane node. Node-file collectors need root, so `ventra run` re-runs
itself under `sudo` (pass `--no-sudo` to skip; those sources are then recorded as gaps).

| Collector | Description |
|-----------|-------------|
| `k8s_apiserver_audit` | API-server audit log from disk, with who-did-what detections |
| `k8s_audit_posture` | Whether API-server audit logging is on and whether the policy is useful |
| `k8s_cluster_state` | All-namespace inventory of workloads, identity, network, storage and admission |
| `k8s_cni_logs` | CNI plugin detection and logs (Calico, Cilium, Flannel, Weave) |
| `k8s_container_logs` | Container logs from the node filesystem, including rotated and dead-pod logs |
| `k8s_etcd` | Datastore posture and logs for etcd, k3s sqlite and microk8s dqlite (never dumps the datastore by default) |
| `k8s_events` | Kubernetes Events across all namespaces (short-lived; default TTL 1h) |
| `k8s_kubelet_logs` | kubelet journal or log: pod admission, image pulls, container lifecycle |
| `k8s_rbac` | RBAC roles and bindings with escalation-path analysis |
| `k8s_runtime_logs` | Container runtime logs (containerd, CRI-O) plus a live `crictl` snapshot |
