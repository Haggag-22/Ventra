"""Generate a realistic synthetic GCP Ventra evidence package for demos and tests.

The data tells one coherent story so the console GCP panels have something meaningful to render:

    A cloud admin's session is used from a foreign IP. The attacker mints a service-account
    key, grants roles/owner to an external service account via SetIamPolicy, reads customer
    exports out of a Cloud Storage bucket, and exfiltrates over a VPC egress flow to a public
    IP. Security Command Center fires findings, and a logging sink is deleted to blind the
    defender. One source (Workspace audit) is intentionally a gap.

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
    GapReason,
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
EXFIL_IP = "185.220.101.45"
LEGIT_IP = "35.190.12.4"
VICTIM_USER = "cloud.admin@ventra-demo.com"
ATTACKER_SA = "exfil-bot@evil-project.iam.gserviceaccount.com"
BUCKET = "ventra-demo-customer-exports"
BASE = datetime(2026, 6, 7, 2, 14, 0, tzinfo=timezone.utc)

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
            "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": "google-cloud-sdk"},
        },
        "_ventra_project_id": PROJECT_ID,
    }


def build_cloud_audit_admin() -> list[dict]:
    proj = f"//cloudresourcemanager.googleapis.com/projects/{PROJECT_ID}"
    sa = f"//iam.googleapis.com/projects/{PROJECT_ID}/serviceAccounts/exfil-bot"
    return [
        _audit(840, "google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", sa),
        _audit(1020, "SetIamPolicy", "cloudresourcemanager.googleapis.com", proj, severity="NOTICE"),
        _audit(1200, "google.logging.v2.ConfigServiceV2.DeleteSink", "logging.googleapis.com",
               f"projects/{PROJECT_ID}/sinks/org-audit", severity="WARNING"),
        _audit(1260, "compute.firewalls.insert", "compute.googleapis.com",
               f"projects/{PROJECT_ID}/global/firewalls/allow-all-ingress", severity="NOTICE"),
    ]


def build_login_events() -> list[dict]:
    events: list[dict] = []
    for i in range(8):
        events.append(_audit(
            -7200 + i * 600, "google.login", "login.googleapis.com",
            f"projects/{PROJECT_ID}", ip=LEGIT_IP, severity="INFO",
        ))
    events.append(_audit(0, "google.login", "login.googleapis.com", f"projects/{PROJECT_ID}",
                         severity="NOTICE"))
    events.append(_audit(
        780, "google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com",
        f"//iam.googleapis.com/projects/{PROJECT_ID}/serviceAccounts/exfil-bot",
        severity="NOTICE",
    ))
    return events


def build_cloud_audit_data() -> list[dict]:
    """Data Access logs — the attacker reading customer export objects out of a bucket."""
    out: list[dict] = []
    for i in range(14):
        out.append(_audit(
            1320 + i * 25, "storage.objects.get", "storage.googleapis.com",
            f"projects/_/buckets/{BUCKET}/objects/customer-export-{i}.csv",
            severity="INFO",
        ))
    return out


def build_vpc_flow() -> list[dict]:
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
            "project", "iam_policy", "cloud_audit_admin", "login_events",
            "cloud_audit_data", "vpc_flow", "scc_findings",
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

        src("project", [("snapshot.json", _write_json(
            sd / "project/snapshot.json", build_project_snapshot()))],
            notes="Project + organization context.")
        src("iam_policy", [("snapshot.json", _write_json(
            sd / "iam_policy/snapshot.json", build_iam_policy_snapshot()))],
            notes="IAM bindings incl. roles/owner granted to external SA.")
        src("cloud_audit_admin", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "cloud_audit_admin/events.jsonl.gz",
                                                build_cloud_audit_admin())),
            ("config.json", _write_json(sd / "cloud_audit_admin/config.json",
                                        {"projects": [{"project_id": PROJECT_ID, "records": 4}]})),
        ], notes="Admin Activity: SetIamPolicy, SA key, sink delete.")
        src("login_events", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "login_events/events.jsonl.gz",
                                                build_login_events())),
            ("config.json", _write_json(sd / "login_events/config.json",
                                        {"projects": [{"project_id": PROJECT_ID}]})),
        ], notes="Login audit incl. foreign-IP session + SA key creation.")
        src("cloud_audit_data", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "cloud_audit_data/events.jsonl.gz",
                                                build_cloud_audit_data())),
            ("config.json", _write_json(sd / "cloud_audit_data/config.json",
                                        {"buckets": [BUCKET]})),
        ], notes="Data Access: customer export object reads.")
        src("vpc_flow", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "vpc_flow/events.jsonl.gz",
                                                build_vpc_flow())),
            ("config.json", _write_json(sd / "vpc_flow/config.json",
                                        {"subnets": [{"name": "default", "region": REGION}]})),
        ], notes="VPC flow incl. large egress to public IP.")
        src("scc_findings", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "scc_findings/events.jsonl.gz",
                                                build_scc_findings())),
            ("config.json", _write_json(sd / "scc_findings/config.json",
                                        {"organization_id": ORG_ID})),
        ], notes="3 Security Command Center findings.")

        # Workspace audit not configured — realistic identity visibility gap.
        manifest.add_source_result(SourceResult(
            name="workspace_audit",
            status=SourceStatus.EMPTY,
            gaps=[("workspace_audit", GapReason.LOGGING_NOT_CONFIGURED,
                   "Workspace audit sharing not enabled — group/admin visibility gap.")],
            notes="Workspace audit logs not configured.",
        ))

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
