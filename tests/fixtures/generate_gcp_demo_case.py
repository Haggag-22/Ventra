"""Generate a realistic synthetic GCP Ventra evidence package for demos and tests.

Techniques are mapped to the Community GCP & Workspace ATT&CK Matrix:
https://github.com/lutzenfried/GCP_ATTACK_Matrix

The data tells one coherent attack story across every GCP collector in the baseline IR pack:

    Discovery (enumerate IAM, buckets, APIs) → initial access via leaked SA key + foreign-IP
    login (OAuth session) → credential access (metadata SSRF, Secret Manager) → privilege
    escalation (actAs, SetIamPolicy backdoor) → execution (Cloud Functions, GKE, Scheduler) →
    persistence (SA keys, SSH metadata, scheduler jobs) → defense evasion (sink delete,
    monitoring disable, firewall widen) → collection/exfil (GCS reads, BigQuery export,
    snapshot access) → SCC findings + VPC/firewall egress.

No real data, no GCP calls. Produces a sealed .tar.zst package via the collector's own
packaging code, so the demo exercises the real EPF path — including artifact[] provenance in
the manifest (mirrors what `ventra collect gcp --pack baseline-ir-gcp` records).

Usage:
    python tests/fixtures/generate_gcp_demo_case.py --out tests/fixtures/
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "collector"))

from collector.engine.acquisition import artifact_refs_for_collectors  # noqa: E402
from collector.lib.chain_of_custody.signing import sign_manifest  # noqa: E402
from collector.lib.models import (  # noqa: E402
    Manifest,
    Operator,
    SourceResult,
    SourceStatus,
    TimeWindow,
    WrittenFile,
)
from collector.lib.packaging.packager import seal_package  # noqa: E402

# Project id carries "gcp" so the sealed archive name matches the `case-CASE-*-gcp-*` glob the
# Makefile ingest target uses.
PROJECT_ID = "ventra-demo-gcp"
ORG_ID = "123456789012"
REGION = "us-central1"
ZONE = "us-central1-a"
ATTACKER_IP = "203.0.113.66"
ATTACKER_IP2 = "198.51.100.23"
EXFIL_IP = "185.220.101.45"
LEGIT_IP = "35.190.12.4"
VICTIM_USER = "cloud.admin@ventra-demo.com"
ATTACKER_SA = "exfil-bot@evil-project.iam.gserviceaccount.com"
COMPROMISED_SA = f"compromised-runner@{PROJECT_ID}.iam.gserviceaccount.com"
BUCKET = "ventra-demo-customer-exports"
BASE = datetime(2026, 6, 7, 2, 14, 0, tzinfo=timezone.utc)

PROJ = f"//cloudresourcemanager.googleapis.com/projects/{PROJECT_ID}"
SA_EXFIL = f"//iam.googleapis.com/projects/{PROJECT_ID}/serviceAccounts/exfil-bot"
SA_RUNNER = f"//iam.googleapis.com/projects/{PROJECT_ID}/serviceAccounts/compromised-runner"
GKE = f"projects/{PROJECT_ID}/locations/{REGION}/clusters/prod-gke"
VM = f"projects/{PROJECT_ID}/zones/{ZONE}/instances/web-vm01"
FUNC = f"projects/{PROJECT_ID}/locations/{REGION}/functions/evil-exfil"
SCHEDULER = f"projects/{PROJECT_ID}/locations/{REGION}/jobs/evil-cron"
SECRET = f"projects/{PROJECT_ID}/secrets/db-credentials"
BQ_DATASET = f"projects/{PROJECT_ID}/datasets/customer_analytics"
SNAPSHOT = f"projects/{PROJECT_ID}/global/snapshots/customer-db-snap-20260601"

rng = random.Random(7331)


def _t(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _audit(
    offset: int,
    method: str,
    service: str,
    resource: str,
    principal: str = VICTIM_USER,
    ip: str = ATTACKER_IP,
    severity: str = "NOTICE",
    user_agent: str = "google-cloud-sdk",
) -> dict:
    return {
        "timestamp": _t(offset),
        "severity": severity,
        "resource": {"type": "project", "labels": {"project_id": PROJECT_ID, "location": REGION}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service,
            "methodName": method,
            "resourceName": resource,
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": user_agent},
        },
        "_ventra_project_id": PROJECT_ID,
    }


def build_cloud_audit_admin() -> list[dict]:
    """TA0007 Discovery, TA0004 Privilege Escalation, TA0003 Persistence, TA0002 Execution,
    TA0005 Defense Evasion, TA0006 Credential Access."""
    events: list[dict] = [
        # TA0007 — Enumerate IAM Policies / Cloud Asset Inventory enumeration
        _audit(260, "google.iam.admin.v1.ListServiceAccounts", "iam.googleapis.com", PROJ),
        _audit(270, "google.iam.admin.v1.GetIamPolicy", "iam.googleapis.com", PROJ),
        _audit(280, "google.cloudresourcemanager.v3.SearchProjects", "cloudresourcemanager.googleapis.com", PROJ),
        _audit(290, "google.cloudasset.v1.AssetService.SearchAllResources", "cloudasset.googleapis.com", PROJ),
        _audit(300, "google.storage.v1.Storage.ListBuckets", "storage.googleapis.com",
               f"projects/{PROJECT_ID}", severity="INFO"),
        _audit(310, "google.api.serviceusage.v1.ServiceUsage.ListServices", "serviceusage.googleapis.com", PROJ),
        _audit(320, "google.compute.instances.list", "compute.googleapis.com",
               f"projects/{PROJECT_ID}/zones/{ZONE}/instances", severity="INFO"),
        _audit(330, "google.container.v1.ClusterManager.ListClusters", "container.googleapis.com",
               f"projects/{PROJECT_ID}/locations/{REGION}/clusters", severity="INFO"),
        # TA0006 — SSRF to metadata server (token theft from compromised workload)
        _audit(360, "compute.instances.getGuestAttributes", "compute.googleapis.com", VM,
               principal=COMPROMISED_SA, ip="10.128.0.5",
               user_agent="curl/7.88.1 metadata.google.internal"),
        # TA0001 / TA0006 — Leaked Service Account Keys used from foreign IP
        _audit(780, "google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", SA_EXFIL),
        _audit(840, "google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", SA_EXFIL,
               principal=ATTACKER_SA, ip=ATTACKER_IP2),
        # TA0004 — Abusing iam.serviceAccounts.actAs + Backdoor IAM Policies (SetIamPolicy)
        _audit(900, "google.iam.admin.v1.SignBlob", "iam.googleapis.com", SA_RUNNER,
               principal=ATTACKER_SA, ip=ATTACKER_IP2),
        _audit(960, "iam.serviceAccounts.actAs", "iam.googleapis.com", SA_RUNNER,
               principal=ATTACKER_SA, ip=ATTACKER_IP2),
        _audit(1020, "SetIamPolicy", "cloudresourcemanager.googleapis.com", PROJ, severity="NOTICE"),
        # TA0003 — Add SSH keys to project metadata / Cloud Scheduler Jobs
        _audit(1080, "compute.projects.setCommonInstanceMetadata", "compute.googleapis.com", PROJ,
               severity="WARNING"),
        _audit(1140, "google.cloud.scheduler.v1.CloudScheduler.CreateJob", "cloudscheduler.googleapis.com",
               SCHEDULER),
        # TA0002 — Cloud Functions/Run Engine Deployment + GKE workload
        _audit(1180, "google.cloudfunctions.v2.FunctionService.CreateFunction", "cloudfunctions.googleapis.com",
               FUNC),
        _audit(1220, "google.cloud.run.v2.Services.CreateService", "run.googleapis.com",
               f"projects/{PROJECT_ID}/locations/{REGION}/services/evil-proxy"),
        _audit(1280, "google.container.v1.ClusterManager.CreatePod", "container.googleapis.com",
               f"{GKE}/k8s/namespaces/default/pods/imds-probe", principal=COMPROMISED_SA, ip="10.128.0.5"),
        # TA0005 — Modify Cloud Logging Rules / Disable Cloud Monitoring / firewall widen
        _audit(1200, "google.logging.v2.ConfigServiceV2.DeleteSink", "logging.googleapis.com",
               f"projects/{PROJECT_ID}/sinks/org-audit", severity="WARNING"),
        _audit(1230, "google.monitoring.v3.AlertPolicyService.DeleteAlertPolicy", "monitoring.googleapis.com",
               f"projects/{PROJECT_ID}/alertPolicies/audit-anomaly", severity="WARNING"),
        _audit(1260, "compute.firewalls.insert", "compute.googleapis.com",
               f"projects/{PROJECT_ID}/global/firewalls/allow-all-ingress", severity="NOTICE"),
        _audit(1290, "compute.subnetworks.setFlowLogsConfig", "compute.googleapis.com",
               f"projects/{PROJECT_ID}/regions/{REGION}/subnetworks/default",
               severity="WARNING"),
        # TA0009 — Snapshot disk access / Clone VM disks via snapshots
        _audit(1400, "compute.snapshots.get", "compute.googleapis.com", SNAPSHOT, severity="INFO"),
        _audit(1410, "compute.disks.createSnapshot", "compute.googleapis.com",
               f"projects/{PROJECT_ID}/zones/{ZONE}/disks/web-vm01-data", severity="NOTICE"),
        # TA0002 — Cloud Build trigger abuse
        _audit(1450, "cloudbuild.googleapis.com.create", "cloudbuild.googleapis.com",
               f"projects/{PROJECT_ID}/builds", principal=ATTACKER_SA, ip=ATTACKER_IP2),
    ]
    return events


def build_cloud_audit_system() -> list[dict]:
    """TA0002 Execution — Compute Engine Startup Scripts / system events."""
    return [
        _audit(1300, "compute.instances.insert", "compute.googleapis.com", VM,
               severity="NOTICE", ip=ATTACKER_IP2),
        _audit(1310, "compute.instances.setMetadata", "compute.googleapis.com", VM,
               severity="WARNING", ip=ATTACKER_IP2,
               user_agent="gcloud compute instances add-metadata"),
        _audit(1320, "compute.instances.start", "compute.googleapis.com", VM,
               severity="INFO", ip=ATTACKER_IP2),
    ]


def build_login_events() -> list[dict]:
    """TA0001 Initial Access — OAuth/Consent patterns, compromised Google Accounts,
    Leaked Service Account Keys."""
    events: list[dict] = []
    for i in range(8):
        events.append(_audit(
            -7200 + i * 600, "google.login", "login.googleapis.com",
            f"projects/{PROJECT_ID}", ip=LEGIT_IP, severity="INFO",
        ))
    # TA0001 — Compromised Google Account from foreign IP
    events.append(_audit(0, "google.login", "login.googleapis.com", f"projects/{PROJECT_ID}",
                         severity="NOTICE"))
    # TA0001 — OAuth/Consent Grant Phishing (admin console session after consent)
    events.append(_audit(120, "google.login", "login.googleapis.com", f"projects/{PROJECT_ID}",
                         severity="NOTICE", user_agent="Mozilla/5.0 OAuth consent follow-up"))
    events.append(_audit(180, "google.admin.AdminService.accountActivity", "admin.googleapis.com",
                         f"projects/{PROJECT_ID}", severity="INFO"))
    # TA0003 / TA0001 — SA key creation tied to compromised session
    events.append(_audit(
        780, "google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", SA_EXFIL,
        severity="NOTICE",
    ))
    return events


def build_cloud_audit_data() -> list[dict]:
    """TA0007 Discovery, TA0006 Credential Access, TA0009 Collection, TA0010 Exfiltration."""
    out: list[dict] = []
    # TA0007 — List Cloud Storage Buckets burst
    for i in range(6):
        out.append(_audit(
            340 + i * 8, "storage.buckets.list", "storage.googleapis.com",
            f"projects/{PROJECT_ID}", severity="INFO",
        ))
    # TA0006 — Extract secrets from Secret Manager
    for secret_ver in ("versions/1", "versions/2", "versions/latest"):
        out.append(_audit(
            400, "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
            "secretmanager.googleapis.com", f"{SECRET}/{secret_ver}",
            principal=ATTACKER_SA, ip=ATTACKER_IP2, severity="NOTICE",
        ))
    # TA0009 / TA0010 — GCS object reads (Copy Data to External Storage)
    for i in range(14):
        out.append(_audit(
            1320 + i * 25, "storage.objects.get", "storage.googleapis.com",
            f"projects/_/buckets/{BUCKET}/objects/customer-export-{i}.csv",
            principal=ATTACKER_SA, ip=ATTACKER_IP2, severity="INFO",
        ))
    for i in range(4):
        out.append(_audit(
            1680 + i * 30, "storage.objects.list", "storage.googleapis.com",
            f"projects/_/buckets/{BUCKET}/objects", principal=ATTACKER_SA, ip=ATTACKER_IP2,
            severity="INFO",
        ))
    # TA0010 — Exfiltrate using BigQuery exports
    out.append(_audit(
        1600, "jobservice.jobcompleted", "bigquery.googleapis.com",
        f"{BQ_DATASET}/jobs/export-customer-001", principal=ATTACKER_SA, ip=ATTACKER_IP2,
        severity="NOTICE",
    ))
    out.append(_audit(
        1620, "google.cloud.bigquery.v2.JobService.InsertJob", "bigquery.googleapis.com",
        f"{BQ_DATASET}/jobs/export-customer-002", principal=ATTACKER_SA, ip=ATTACKER_IP2,
        severity="NOTICE",
    ))
    return out


def build_firewall_logs() -> list[dict]:
    """TA0005 Defense Evasion / TA0010 — firewall hits incl. scan probes and exfil allow."""
    out: list[dict] = []

    def fw(offset: int, src: str, dst: str, action: str, rule: str) -> dict:
        return {
            "timestamp": _t(offset),
            "severity": "INFO" if action == "ALLOW" else "WARNING",
            "resource": {
                "type": "gce_subnetwork",
                "labels": {"project_id": PROJECT_ID, "subnetwork_name": "default", "zone": ZONE},
            },
            "jsonPayload": {
                "connection": {"src_ip": src, "dest_ip": dst, "dest_port": 443, "protocol": 6},
                "disposition": action,
                "rule_details": {"reference": rule},
            },
            "_ventra_project_id": PROJECT_ID,
        }

    # TA0007 — port scan probes (denied)
    for i, port in enumerate([22, 3389, 445, 5985, 8080]):
        out.append({
            "timestamp": _t(200 + i * 12),
            "severity": "WARNING",
            "resource": {
                "type": "gce_subnetwork",
                "labels": {"project_id": PROJECT_ID, "subnetwork_name": "default", "zone": ZONE},
            },
            "jsonPayload": {
                "connection": {
                    "src_ip": ATTACKER_IP, "dest_ip": "10.128.0.5",
                    "dest_port": port, "protocol": 6,
                },
                "disposition": "DENY",
                "rule_details": {"reference": "default-deny-ingress"},
            },
            "_ventra_project_id": PROJECT_ID,
        })
    for i in range(8):
        out.append(fw(820 + i * 25, "10.128.0.5", "10.128.0.20", "ALLOW", "allow-internal"))
    for i in range(6):
        out.append(fw(1550 + i * 45, "10.128.0.5", EXFIL_IP, "ALLOW", "allow-all-ingress"))
    return out


def build_vpc_flow() -> list[dict]:
    """TA0010 Exfiltration — VPC flow incl. internal baseline + large egress."""
    out: list[dict] = []

    def flow(src: str, dst: str, offset: int, nbytes: int, port: int = 443) -> dict:
        return {
            "timestamp": _t(offset),
            "severity": "INFO",
            "resource": {"type": "gce_subnetwork",
                         "labels": {"project_id": PROJECT_ID, "zone": ZONE}},
            "jsonPayload": {
                "connection": {"src_ip": src, "dest_ip": dst, "dest_port": port, "protocol": 6},
                "bytes_sent": str(nbytes),
                "reporter": "SRC",
            },
            "_ventra_project_id": PROJECT_ID,
        }

    for i in range(18):
        out.append(flow("10.128.0.5", "10.128.0.20", 800 + i * 20, rng.randint(500, 6000)))
    for i in range(10):
        out.append(flow("10.128.0.5", EXFIL_IP, 1500 + i * 40, rng.randint(6_000_000, 14_000_000)))
    return out


def build_scc_findings() -> list[dict]:
    """SCC-relevant misconfig / detection signals aligned to matrix techniques."""
    src = f"organizations/{ORG_ID}/sources/55555"

    def finding(fid: str, category: str, severity: str, offset: int, desc: str) -> dict:
        return {
            "name": f"{src}/findings/{fid}",
            "parent": src,
            "category": category,
            "severity": severity,
            "state": "ACTIVE",
            "eventTime": _t(offset),
            "createTime": _t(offset),
            "description": desc,
            "resourceName": f"//cloudresourcemanager.googleapis.com/projects/{PROJECT_ID}",
            "_ventra_organization_id": ORG_ID,
        }

    return [
        finding("f-001", "Persistence: IAM Anomalous Grant", "HIGH", 1040,
                "roles/owner granted to an external service account."),
        finding("f-002", "Exfiltration: BigQuery Data Extraction", "CRITICAL", 1560,
                "Large egress of storage objects to an external IP."),
        finding("f-003", "Defense Evasion: Logging Sink Deleted", "HIGH", 1210,
                "An organization audit logging sink was deleted."),
        finding("f-004", "Privilege Escalation: Service Account ActAs", "HIGH", 970,
                "External SA invoked iam.serviceAccounts.actAs on a project SA."),
        finding("f-005", "Initial Access: Exposed Service Account Key", "HIGH", 850,
                "Service account key created and used from a foreign IP."),
        finding("f-006", "Persistence: Public SSH Key in Metadata", "MEDIUM", 1090,
                "SSH public key added to project instance metadata."),
        finding("f-007", "Execution: Suspicious Cloud Function Deploy", "MEDIUM", 1190,
                "New Cloud Function deployed by an external service account."),
        finding("f-008", "Credential Access: Secret Manager Access", "HIGH", 410,
                "Multiple Secret Manager versions accessed by external SA."),
    ]


def build_iam_policy_snapshot() -> dict:
    return {
        "projects": [
            {
                "project_id": PROJECT_ID,
                "etag": "BwYabc123",
                "bindings": [
                    {"role": "roles/owner",
                     "members": [f"user:{VICTIM_USER}", f"serviceAccount:{ATTACKER_SA}"]},
                    {"role": "roles/viewer", "members": ["user:analyst@ventra-demo.com"]},
                    {"role": "roles/storage.objectViewer",
                     "members": [f"serviceAccount:{ATTACKER_SA}"]},
                    {"role": "roles/iam.serviceAccountUser",
                     "members": [f"serviceAccount:{ATTACKER_SA}"]},
                    {"role": "roles/secretmanager.secretAccessor",
                     "members": [f"serviceAccount:{ATTACKER_SA}"]},
                ],
                "project_iam": {
                    "etag": "BwYabc123",
                    "bindings": [
                        {"role": "roles/owner",
                         "members": [f"user:{VICTIM_USER}", f"serviceAccount:{ATTACKER_SA}"]},
                        {"role": "roles/viewer", "members": ["user:analyst@ventra-demo.com"]},
                        {"role": "roles/storage.objectViewer",
                         "members": [f"serviceAccount:{ATTACKER_SA}"]},
                        {"role": "roles/iam.serviceAccountUser",
                         "members": [f"serviceAccount:{ATTACKER_SA}"]},
                        {"role": "roles/secretmanager.secretAccessor",
                         "members": [f"serviceAccount:{ATTACKER_SA}"]},
                    ],
                },
                "service_accounts": [
                    {
                        "name": SA_RUNNER,
                        "email": COMPROMISED_SA,
                        "displayName": "Compromised workload runner",
                        "keys": [
                            {
                                "name": f"{SA_RUNNER}/keys/abc123",
                                "keyAlgorithm": "KEY_ALG_RSA_2048",
                                "keyOrigin": "GOOGLE_PROVIDED",
                                "keyType": "SYSTEM_MANAGED",
                                "validAfterTime": "2026-01-01T00:00:00Z",
                                "validBeforeTime": "2026-07-01T00:00:00Z",
                                "disabled": False,
                            },
                            {
                                "name": f"{SA_RUNNER}/keys/def456",
                                "keyAlgorithm": "KEY_ALG_RSA_2048",
                                "keyOrigin": "USER_PROVIDED",
                                "keyType": "USER_MANAGED",
                                "validAfterTime": "2026-06-07T08:00:00Z",
                                "validBeforeTime": "",
                                "disabled": False,
                            },
                        ],
                        "iam_policy": {
                            "etag": "BwYsa456",
                            "bindings": [
                                {
                                    "role": "roles/iam.serviceAccountUser",
                                    "members": [f"serviceAccount:{ATTACKER_SA}"],
                                }
                            ],
                        },
                    },
                    {
                        "name": SA_EXFIL,
                        "email": ATTACKER_SA,
                        "displayName": "External exfil bot",
                        "keys": [
                            {
                                "name": f"{SA_EXFIL}/keys/ghi789",
                                "keyAlgorithm": "KEY_ALG_RSA_2048",
                                "keyOrigin": "USER_PROVIDED",
                                "keyType": "USER_MANAGED",
                                "validAfterTime": "2026-06-07T08:20:00Z",
                                "validBeforeTime": "",
                                "disabled": False,
                            }
                        ],
                        "iam_policy": {"etag": "BwYsa789", "bindings": []},
                    },
                ],
                "custom_roles": [
                    {
                        "name": f"projects/{PROJECT_ID}/roles/ventraCustomViewer",
                        "title": "Ventra custom viewer",
                        "description": "Read-only custom role for demo workloads",
                        "includedPermissions": ["storage.objects.get", "storage.objects.list"],
                        "stage": "GA",
                    }
                ],
            }
        ]
    }


def build_project_snapshot() -> dict:
    return {
        "organization_id": ORG_ID,
        "operator_principal": "ventra-collector@ventra-demo-gcp.iam.gserviceaccount.com",
        "default_project": PROJECT_ID,
        "projects_in_scope": [PROJECT_ID],
        "projects": [
            {"project_id": PROJECT_ID, "name": "Ventra Demo Prod", "state": "ACTIVE",
             "project_number": "987654321000"}
        ],
    }


def _write_gz_jsonl(path: Path, records: list[dict]) -> WrittenFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(filename=path, mode="wb", mtime=0) as gz:
        for r in records:
            gz.write((json.dumps(r, separators=(",", ":")) + "\n").encode())
    data = path.read_bytes()
    return WrittenFile(path=path.name, sha256=hashlib.sha256(data).hexdigest(),
                       bytes=len(data), record_count=len(records))


def _write_json(path: Path, obj) -> WrittenFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, indent=2).encode()
    path.write_bytes(payload)
    return WrittenFile(path=path.name, sha256=hashlib.sha256(payload).hexdigest(),
                       bytes=len(payload))


def generate(out_dir: Path, case_id: str = "CASE-2026-GCP7") -> Path:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ventra-gcp-demo-") as tmp:
        staging = Path(tmp)
        sources = [
            "project", "iam_policy", "cloud_audit_admin", "cloud_audit_system", "login_events",
            "cloud_audit_data", "vpc_flow", "firewall_logs", "scc_findings",
        ]
        manifest = Manifest(
            schema_version="1.0.0", tool_version="0.1.0", case_id=case_id,
            cloud="gcp", account_id=PROJECT_ID, account_alias=PROJECT_ID,
            partition="gcp", org_id=ORG_ID, regions=[REGION],
            operator=Operator(
                principal_arn="gcp-sa:ventra-collector@ventra-demo-gcp.iam.gserviceaccount.com",
                user_id=PROJECT_ID, source_ip="100.64.0.10"),
            started_at=_t(-10), completed_at=_t(2000),
            profile_name="all",
            host_environment="local", host_os="macOS 15",
            host_runtime="python 3.11.8",
            time_window=TimeWindow(since=BASE - timedelta(days=3)),
        )
        manifest.artifacts = artifact_refs_for_collectors("gcp", sources)

        def src(dirname, files, status=SourceStatus.COLLECTED, gaps=None, notes=""):
            wfs = []
            for fname, wf in files:
                wf.path = f"sources/{dirname}/{fname}"
                wfs.append(wf)
            manifest.add_source_result(SourceResult(name=dirname, status=status, files=wfs,
                                                    gaps=gaps or [], notes=notes))

        sd = staging / "sources"

        admin = build_cloud_audit_admin()
        system = build_cloud_audit_system()
        login = build_login_events()
        data = build_cloud_audit_data()
        vpc = build_vpc_flow()
        fw = build_firewall_logs()
        scc = build_scc_findings()

        src("project", [("snapshot.json", _write_json(
            sd / "project/snapshot.json", build_project_snapshot()))],
            notes="Project + organization context.")
        src("iam_policy", [("snapshot.json", _write_json(
            sd / "iam_policy/snapshot.json", build_iam_policy_snapshot()))],
            notes="IAM snapshot incl. actAs + external SA owner grant.")
        src("cloud_audit_admin", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "cloud_audit_admin/events.jsonl.gz", admin)),
            ("config.json", _write_json(sd / "cloud_audit_admin/config.json",
                                        {"projects": [{"project_id": PROJECT_ID,
                                                       "records": len(admin)}]})),
        ], notes="Admin Activity: discovery, escalation, execution, evasion (GCP Attack Matrix).")
        src("cloud_audit_system", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "cloud_audit_system/events.jsonl.gz", system)),
            ("config.json", _write_json(sd / "cloud_audit_system/config.json",
                                        {"projects": [{"project_id": PROJECT_ID,
                                                       "records": len(system)}]})),
        ], notes="System Event: startup script / VM metadata changes.")
        src("login_events", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "login_events/events.jsonl.gz", login)),
            ("config.json", _write_json(sd / "login_events/config.json",
                                        {"projects": [{"project_id": PROJECT_ID}]})),
        ], notes="Login audit: foreign IP, OAuth consent, SA key (Matrix TA0001).")
        src("cloud_audit_data", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "cloud_audit_data/events.jsonl.gz", data)),
            ("config.json", _write_json(sd / "cloud_audit_data/config.json",
                                        {"buckets": [BUCKET]})),
        ], notes="Data Access: discovery burst, Secret Manager, GCS, BigQuery export.")
        src("vpc_flow", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "vpc_flow/events.jsonl.gz", vpc)),
            ("config.json", _write_json(sd / "vpc_flow/config.json",
                                        {"subnets": [{"name": "default", "region": REGION}]})),
        ], notes="VPC flow incl. large egress to public IP.")
        src("firewall_logs", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "firewall_logs/events.jsonl.gz", fw)),
            ("config.json", _write_json(sd / "firewall_logs/config.json",
                                        {"subnets": [{"name": "default", "region": REGION}]})),
        ], notes="Firewall hits: scan probes + exfil allow (Matrix TA0005/TA0010).")
        src("scc_findings", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "scc_findings/events.jsonl.gz", scc)),
            ("config.json", _write_json(sd / "scc_findings/config.json",
                                        {"organization_id": ORG_ID})),
        ], notes=f"{len(scc)} Security Command Center findings.")

        (staging / "collection.log").write_text(
            "\n".join(json.dumps({"collector": s["name"], "status": s["status"]})
                      for s in manifest.sources) + "\n", encoding="utf-8")
        manifest_path = staging / "manifest.json"
        manifest.write(manifest_path)
        sign_manifest(manifest_path, None)
        result = seal_package(staging, out_dir, case_id, PROJECT_ID)
        return result.path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a synthetic GCP Ventra demo package.")
    ap.add_argument("--out", default="tests/fixtures", help="Output directory.")
    ap.add_argument("--case", default="CASE-2026-GCP7")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = generate(out, args.case)
    print(f"Wrote GCP demo package: {path}")
    print(f"  size: {path.stat().st_size:,} bytes")
    print(f"  case_id: {args.case}")
    print("  cloud: gcp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
