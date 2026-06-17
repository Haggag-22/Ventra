"""Generate a realistic synthetic Azure/M365 Ventra evidence package for demos and tests.

The data tells one coherent story so the console Azure panels have something meaningful to render:

    A finance admin's Entra session is hijacked from a foreign IP. The attacker grants OAuth
    consent to a malicious app, adds service-principal credentials, escalates via RBAC role
    assignment, reads customer exports from blob storage, accesses mailboxes (UAL), and
    exfiltrates over VNet flow egress. Defender fires along the way.

No real data, no Azure calls. Produces a sealed .tar.zst package via the collector's own
packaging code, so the demo exercises the real EPF path.

Usage:
    python tests/fixtures/generate_azure_demo_case.py --out tests/fixtures/
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

TENANT_ID = "11111111-2222-3333-4444-555555555555"
TENANT_NAME = "contoso-demo"
SUBSCRIPTION_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
REGION = "eastus"
ATTACKER_IP = "203.0.113.66"
ATTACKER_IP2 = "198.51.100.23"
LEGIT_IP = "52.94.236.10"
EXFIL_IP = "185.220.101.45"
VICTIM_USER = "finance.admin@contoso-demo.com"
MALICIOUS_APP = "EvilBackupSync"
MALICIOUS_APP_ID = "app-evil-backup-sync-666"
BASE = datetime(2026, 6, 7, 2, 14, 0, tzinfo=timezone.utc)

rng = random.Random(4242)


def _t(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_entra_signin() -> list[dict]:
    events: list[dict] = []
    for i in range(25):
        events.append({
            "id": f"baseline-{i}",
            "createdDateTime": (BASE - timedelta(days=2) + timedelta(hours=i)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "userPrincipalName": VICTIM_USER,
            "ipAddress": LEGIT_IP,
            "appDisplayName": "Microsoft Office",
            "status": {"errorCode": 0},
            "location": {"countryOrRegion": "US", "city": "Seattle"},
        })
    events.append({
        "id": "sign-attacker-1",
        "createdDateTime": _t(0),
        "userPrincipalName": VICTIM_USER,
        "ipAddress": ATTACKER_IP,
        "appDisplayName": "Microsoft Office",
        "status": {"errorCode": 0},
        "location": {"countryOrRegion": "RU", "city": "Moscow"},
        "riskDetail": "unlikelyTravel",
    })
    events.append({
        "id": "sign-attacker-fail",
        "createdDateTime": _t(30),
        "userPrincipalName": VICTIM_USER,
        "ipAddress": ATTACKER_IP,
        "appDisplayName": "Azure Portal",
        "status": {"errorCode": 50126},
        "location": {"countryOrRegion": "RU", "city": "Moscow"},
    })
    events.append({
        "id": "sign-attacker-2",
        "createdDateTime": _t(120),
        "userPrincipalName": VICTIM_USER,
        "ipAddress": ATTACKER_IP,
        "appDisplayName": "Azure Portal",
        "status": {"errorCode": 0},
        "location": {"countryOrRegion": "RU", "city": "Moscow"},
    })
    return events


def build_entra_audit() -> list[dict]:
    def audit(when: str, action: str, target: str, target_type: str = "Application") -> dict:
        return {
            "id": f"audit-{when}",
            "activityDateTime": when,
            "activityDisplayName": action,
            "operationType": action.split()[0],
            "initiatedBy": {
                "user": {"userPrincipalName": VICTIM_USER, "displayName": "Finance Admin"},
            },
            "targetResources": [{"displayName": target, "id": target, "type": target_type}],
        }

    return [
        audit(_t(300), "Get directory role assignments", "DirectoryRole"),
        audit(_t(780), "Consent to application", MALICIOUS_APP),
        audit(_t(900), "Add service principal credentials", MALICIOUS_APP, "ServicePrincipal"),
        audit(_t(960), "Add app role assignment to service principal", MALICIOUS_APP),
        audit(_t(1140), "Add member to role", "Contributor"),
    ]


def build_activity_log() -> list[dict]:
    def act(when: str, op: str, caller: str, ip: str, resource: str) -> dict:
        return {
            "eventTimestamp": when,
            "operationName": {"value": op, "localizedValue": op},
            "status": {"value": "Succeeded"},
            "caller": caller,
            "callerIpAddress": ip,
            "resourceId": resource,
            "subscriptionId": SUBSCRIPTION_ID,
        }

    sub = f"/subscriptions/{SUBSCRIPTION_ID}"
    rg = f"{sub}/resourceGroups/prod-rg"
    storage = f"{rg}/providers/Microsoft.Storage/storageAccounts/clientprodblobs"
    return [
        act(_t(360), "Microsoft.Authorization/roleAssignments/read", VICTIM_USER, ATTACKER_IP,
            f"{sub}/providers/Microsoft.Authorization/roleAssignments"),
        act(_t(1020), "Microsoft.Authorization/roleAssignments/write", VICTIM_USER, ATTACKER_IP,
            f"{sub}/providers/Microsoft.Authorization/roleAssignments/ra-evil-001"),
        act(_t(1080), "Microsoft.Storage/storageAccounts/listKeys/action", VICTIM_USER,
            ATTACKER_IP2, storage),
        act(_t(1200), "Microsoft.Insights/diagnosticSettings/delete", VICTIM_USER, ATTACKER_IP2,
            f"{storage}/providers/Microsoft.Insights/diagnosticSettings/storage-logs"),
        act(_t(1320), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            VICTIM_USER, ATTACKER_IP2,
            f"{storage}/blobServices/default/containers/backups/blobs/customer-export-1.csv"),
        act(_t(1380), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            VICTIM_USER, ATTACKER_IP2,
            f"{storage}/blobServices/default/containers/backups/blobs/customer-export-2.csv"),
        act(_t(1440), "Microsoft.Compute/virtualMachines/runCommand/action", VICTIM_USER,
            ATTACKER_IP2, f"{rg}/providers/Microsoft.Compute/virtualMachines/web-vm01"),
    ]


def build_defender() -> list[dict]:
    return [
        {
            "properties": {
                "alertDisplayName": "Suspicious sign-in from unfamiliar location",
                "severity": "High",
                "startTimeUtc": _t(60),
                "compromisedEntity": VICTIM_USER,
                "alertType": "SuspiciousSignIn",
                "resourceLocation": REGION,
            },
            "_ventra_subscription_id": SUBSCRIPTION_ID,
        },
        {
            "properties": {
                "alertDisplayName": "Possible persistence via service principal credentials",
                "severity": "High",
                "startTimeUtc": _t(920),
                "compromisedEntity": MALICIOUS_APP,
                "alertType": "CredentialAddedToServicePrincipal",
                "resourceLocation": REGION,
            },
            "_ventra_subscription_id": SUBSCRIPTION_ID,
        },
        {
            "properties": {
                "alertDisplayName": "Anomalous blob read volume",
                "severity": "Medium",
                "startTimeUtc": _t(1400),
                "compromisedEntity": "clientprodblobs",
                "alertType": "StorageAnomaly",
                "resourceLocation": REGION,
            },
            "_ventra_subscription_id": SUBSCRIPTION_ID,
        },
    ]


def build_vnet_flow() -> list[dict]:
    rid = (f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/prod-rg/providers/"
           f"Microsoft.Network/virtualNetworks/prod-vnet/flowLogs/fl-prod")
    out: list[dict] = []
    for i in range(20):
        out.append({
            "srcaddr": "10.0.2.4",
            "dstaddr": "10.0.3.10",
            "dstport": 443,
            "action": "ALLOW",
            "bytes": rng.randint(500, 8000),
            "timestamp": _t(800 + i * 30),
            "resource_id": rid,
            "_ventra_region": REGION,
        })
    for i in range(10):
        nbytes = rng.randint(5_000_000, 12_000_000)
        out.append({
            "srcaddr": "10.0.2.4",
            "dstaddr": EXFIL_IP,
            "dstport": 443,
            "action": "ALLOW",
            "bytes": nbytes,
            "timestamp": _t(1500 + i * 45),
            "resource_id": rid,
            "_ventra_region": REGION,
        })
    for i in range(8):
        out.append({
            "srcaddr": ATTACKER_IP,
            "dstaddr": "10.0.1.5",
            "dstport": rng.choice([22, 3389, 445]),
            "action": "DENY",
            "bytes": rng.randint(40, 200),
            "timestamp": _t(200 + i * 20),
            "resource_id": rid,
            "_ventra_region": REGION,
        })
    return out


def build_unified_audit() -> list[dict]:
    storage = (f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/prod-rg/providers/"
               f"Microsoft.Storage/storageAccounts/clientprodblobs")
    return [
        {
            "CreationTime": _t(780),
            "Operation": "Consent to application.",
            "Workload": "AzureActiveDirectory",
            "UserId": VICTIM_USER,
            "ClientIP": ATTACKER_IP,
            "ResultStatus": "Success",
            "ObjectId": MALICIOUS_APP_ID,
            "OrganizationId": TENANT_ID,
        },
        {
            "CreationTime": _t(1560),
            "Operation": "MailItemsAccessed",
            "Workload": "Exchange",
            "UserId": VICTIM_USER,
            "ClientIP": ATTACKER_IP2,
            "ResultStatus": "Succeeded",
            "ObjectId": "msg-customer-list-001",
            "OrganizationId": TENANT_ID,
        },
        {
            "CreationTime": _t(1620),
            "Operation": "Send",
            "Workload": "Exchange",
            "UserId": VICTIM_USER,
            "ClientIP": ATTACKER_IP2,
            "ResultStatus": "Succeeded",
            "ObjectId": "msg-exfil-draft",
            "OrganizationId": TENANT_ID,
        },
        {
            "CreationTime": _t(900),
            "Operation": "Add service principal credentials.",
            "Workload": "AzureActiveDirectory",
            "UserId": VICTIM_USER,
            "ClientIP": ATTACKER_IP,
            "ResultStatus": "Success",
            "ObjectId": MALICIOUS_APP_ID,
            "OrganizationId": TENANT_ID,
        },
    ]


def build_oauth_consent() -> list[dict]:
    return [{
        "clientId": MALICIOUS_APP_ID,
        "principalId": VICTIM_USER,
        "consentType": "Principal",
        "scope": "Mail.Read Mail.Send Files.ReadWrite.All",
        "resourceId": "00000003-0000-0000-c000-000000000000",
    }]


def build_storage_access() -> list[dict]:
    storage = (f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/prod-rg/providers/"
               f"Microsoft.Storage/storageAccounts/clientprodblobs")
    out: list[dict] = []
    for i in range(12):
        out.append({
            "time": _t(1320 + i * 35),
            "resourceId": storage,
            "category": "StorageRead",
            "properties": {
                "operationName": "GetBlob",
                "uri": f"https://clientprodblobs.blob.core.windows.net/backups/customer-export-{i}.csv",
                "callerIpAddress": ATTACKER_IP2,
                "authenticationType": "OAuth",
                "statusCode": "200",
            },
        })
    return out


def build_entra_directory_snapshot() -> dict:
    return {
        "users": [
            {"id": "u-finance", "userPrincipalName": VICTIM_USER, "displayName": "Finance Admin",
             "accountEnabled": True},
            {"id": "u-admin", "userPrincipalName": "it.admin@contoso-demo.com",
             "displayName": "IT Admin", "accountEnabled": True},
        ],
        "groups": [
            {"id": "g-finance", "displayName": "Finance Team"},
        ],
        "applications": [
            {"id": MALICIOUS_APP_ID, "displayName": MALICIOUS_APP,
             "appId": MALICIOUS_APP_ID, "createdDateTime": _t(700)},
            {"id": "app-legit-001", "displayName": "Contoso HR Portal",
             "appId": "app-legit-001"},
        ],
        "service_principals": [
            {"id": "sp-evil-666", "displayName": MALICIOUS_APP, "appId": MALICIOUS_APP_ID,
             "servicePrincipalType": "Application"},
        ],
    }


def build_rbac_snapshot() -> dict:
    return {
        "subscriptions": [SUBSCRIPTION_ID],
        "role_definitions": [
            {"roleName": "Contributor", "roleType": "BuiltInRole",
             "_ventra_subscription_id": SUBSCRIPTION_ID},
            {"roleName": "Owner", "roleType": "BuiltInRole",
             "_ventra_subscription_id": SUBSCRIPTION_ID},
        ],
        "role_assignments": [
            {"principalId": "u-finance", "roleDefinitionName": "Reader",
             "scope": f"/subscriptions/{SUBSCRIPTION_ID}",
             "_ventra_subscription_id": SUBSCRIPTION_ID},
            {"principalId": "sp-evil-666", "roleDefinitionName": "Contributor",
             "scope": f"/subscriptions/{SUBSCRIPTION_ID}",
             "_ventra_subscription_id": SUBSCRIPTION_ID, "createdOn": _t(1020)},
        ],
    }


def build_subscription_snapshot() -> dict:
    return {
        "tenant_id": TENANT_ID,
        "tenant_name": TENANT_NAME,
        "operator_principal": "sp-ventra-collector-demo",
        "subscriptions_in_scope": [SUBSCRIPTION_ID],
        "subscriptions": [{
            "subscription_id": SUBSCRIPTION_ID,
            "display_name": "Contoso Production",
            "tenant_id": TENANT_ID,
            "state": "Enabled",
        }],
    }


def build_resource_graph_snapshot() -> dict:
    sub = f"/subscriptions/{SUBSCRIPTION_ID}"
    rg = f"{sub}/resourceGroups/prod-rg"
    return {
        "subscriptions": [SUBSCRIPTION_ID],
        "resources": [
            {"id": f"{rg}/providers/Microsoft.Storage/storageAccounts/clientprodblobs",
             "name": "clientprodblobs", "type": "Microsoft.Storage/storageAccounts",
             "location": REGION, "resourceGroup": "prod-rg",
             "subscriptionId": SUBSCRIPTION_ID},
            {"id": f"{rg}/providers/Microsoft.Network/virtualNetworks/prod-vnet",
             "name": "prod-vnet", "type": "Microsoft.Network/virtualNetworks",
             "location": REGION, "resourceGroup": "prod-rg",
             "subscriptionId": SUBSCRIPTION_ID},
            {"id": f"{rg}/providers/Microsoft.Compute/virtualMachines/web-vm01",
             "name": "web-vm01", "type": "Microsoft.Compute/virtualMachines",
             "location": REGION, "resourceGroup": "prod-rg",
             "subscriptionId": SUBSCRIPTION_ID},
        ],
    }


def build_diag_posture() -> dict:
    """Diagnostic routing posture — several sources intentionally unrouted (realistic gaps)."""
    return {
        "app_gateway": {
            "resources_total": 1,
            "routed_to_storage": 0,
            "log_analytics_only": 1,
            "event_hub_only": 0,
            "no_routing": 0,
            "sample": ["prod-appgw:log_analytics"],
        },
        "front_door": {
            "resources_total": 0,
            "routed_to_storage": 0,
            "log_analytics_only": 0,
            "event_hub_only": 0,
            "no_routing": 0,
            "sample": [],
        },
        "dns": {
            "resources_total": 2,
            "routed_to_storage": 0,
            "log_analytics_only": 0,
            "event_hub_only": 0,
            "no_routing": 2,
            "sample": ["contoso.com:none", "internal.contoso-demo.com:none"],
        },
        "storage_access": {
            "resources_total": 1,
            "routed_to_storage": 1,
            "log_analytics_only": 0,
            "event_hub_only": 0,
            "no_routing": 0,
            "sample": ["clientprodblobs:storage"],
        },
        "key_vault": {
            "resources_total": 1,
            "routed_to_storage": 0,
            "log_analytics_only": 0,
            "event_hub_only": 0,
            "no_routing": 1,
            "sample": ["prod-kv:none"],
        },
        "aks_audit": {
            "resources_total": 0,
            "routed_to_storage": 0,
            "log_analytics_only": 0,
            "event_hub_only": 0,
            "no_routing": 0,
            "sample": [],
        },
        "azure_firewall": {
            "resources_total": 0,
            "routed_to_storage": 0,
            "log_analytics_only": 0,
            "event_hub_only": 0,
            "no_routing": 0,
            "sample": [],
        },
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


def generate(out_dir: Path, case_id: str = "CASE-2026-AZ42") -> Path:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ventra-azure-demo-") as tmp:
        staging = Path(tmp)
        manifest = Manifest(
            schema_version="1.0.0", tool_version="0.1.0", case_id=case_id,
            cloud="azure", account_id=TENANT_ID, account_alias=TENANT_NAME,
            partition="azure", org_id=TENANT_ID, regions=[REGION],
            operator=Operator(
                principal_arn=f"azure-sp:sp-ventra-collector-demo",
                user_id=TENANT_ID, source_ip="100.64.0.10"),
            started_at=_t(-10), completed_at=_t(2000),
            profile_name="all",
            host_environment="local", host_os="macOS 15",
            host_runtime="python 3.11.8",
            time_window=TimeWindow(since=BASE - timedelta(days=3)),
        )

        def src(dirname, files, status=SourceStatus.COLLECTED, gaps=None, notes=""):
            wfs = []
            for fname, wf in files:
                wf.path = f"sources/{dirname}/{fname}"
                wfs.append(wf)
            manifest.add_source_result(SourceResult(name=dirname, status=status, files=wfs,
                                                    gaps=gaps or [], notes=notes))

        sd = staging / "sources"

        src("subscription", [("snapshot.json", _write_json(
            sd / "subscription/snapshot.json", build_subscription_snapshot()))],
            notes="Tenant + subscription context.")
        src("entra_signin", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "entra_signin/events.jsonl.gz",
                                                build_entra_signin())),
            ("_meta.json", _write_json(sd / "entra_signin/_meta.json",
                                        {"source": "entra_signin", "records": 28})),
        ], notes="Sign-in logs incl. foreign-IP session.")
        src("entra_audit", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "entra_audit/events.jsonl.gz",
                                                build_entra_audit())),
            ("_meta.json", _write_json(sd / "entra_audit/_meta.json",
                                        {"source": "entra_audit", "records": 5})),
        ], notes="OAuth consent + SP credential add.")
        src("activity_log", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "activity_log/events.jsonl.gz",
                                                 build_activity_log())),
            ("_meta.json", _write_json(sd / "activity_log/_meta.json",
                                       {"source": "activity_log", "records": 7})),
        ], notes="RBAC escalation + blob reads + diag delete.")
        src("defender", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "defender/events.jsonl.gz",
                                                build_defender())),
            ("config.json", _write_json(sd / "defender/config.json",
                                         {"subscriptions": [{"subscription_id": SUBSCRIPTION_ID,
                                                             "alerts": 3}]})),
        ], notes="3 Defender alerts.")
        src("vnet_flow", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "vnet_flow/events.jsonl.gz",
                                                build_vnet_flow())),
            ("config.json", _write_json(sd / "vnet_flow/config.json", {
                "flow_logs": [{"name": "fl-prod", "target": "prod-vnet", "enabled": True}],
            })),
        ], notes="VNet flow incl. large egress to public IP.")
        src("unified_audit", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "unified_audit/events.jsonl.gz",
                                                build_unified_audit())),
            ("_meta.json", _write_json(sd / "unified_audit/_meta.json",
                                        {"source": "unified_audit", "records": 4})),
        ], notes="UAL: consent + MailItemsAccessed + Send.")
        src("oauth_consent", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "oauth_consent/events.jsonl.gz",
                                                 build_oauth_consent())),
            ("_meta.json", _write_json(sd / "oauth_consent/_meta.json",
                                        {"source": "oauth_consent", "records": 1})),
        ], notes="Illicit OAuth permission grant inventory.")
        src("storage_access", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "storage_access/events.jsonl.gz",
                                               build_storage_access())),
        ], notes="Blob read exfil from storage diagnostics.")
        src("entra_directory", [("snapshot.json", _write_json(
            sd / "entra_directory/snapshot.json", build_entra_directory_snapshot()))],
            notes="Users, apps, malicious service principal.")
        src("rbac", [("snapshot.json", _write_json(
            sd / "rbac/snapshot.json", build_rbac_snapshot()))],
            notes="Contributor role assigned to malicious SP.")
        src("resource_graph", [("snapshot.json", _write_json(
            sd / "resource_graph/snapshot.json", build_resource_graph_snapshot()))],
            notes="ARM inventory snapshot.")

        # Diagnostic posture — records gaps for sources not routed to Storage.
        diag_gaps = [
            ("app_gateway", GapReason.LOGGING_NOT_CONFIGURED,
             "1/1 resource(s) route logs to Log Analytics only — not collectible via Storage."),
            ("front_door", GapReason.NOT_PRESENT, "No Microsoft.Network/frontDoors resources in scope."),
            ("dns", GapReason.LOGGING_NOT_CONFIGURED,
             "No diagnostic settings on any of 2 resource(s)."),
            ("key_vault", GapReason.LOGGING_NOT_CONFIGURED,
             "No diagnostic settings on any of 1 resource(s)."),
            ("aks_audit", GapReason.NOT_PRESENT,
             "No Microsoft.ContainerService/managedClusters resources in scope."),
            ("azure_firewall", GapReason.NOT_PRESENT,
             "No Microsoft.Network/azureFirewalls resources in scope."),
        ]
        src("diag_posture", [("config.json", _write_json(
            sd / "diag_posture/config.json", build_diag_posture()))],
            gaps=diag_gaps, notes="Diagnostic routing posture for uncollected log sources.")

        # NSG flow not enabled — realistic network visibility gap.
        manifest.add_source_result(SourceResult(
            name="nsg_flow",
            status=SourceStatus.EMPTY,
            gaps=[("nsg_flow", GapReason.LOGGING_NOT_CONFIGURED,
                   "No enabled NSG flow logs in scope — network flow visibility gap.")],
            notes="NSG flow logs not configured.",
        ))

        (staging / "collection.log").write_text(
            "\n".join(json.dumps({"collector": s["name"], "status": s["status"]})
                      for s in manifest.sources) + "\n", encoding="utf-8")
        manifest_path = staging / "manifest.json"
        manifest.write(manifest_path)
        sign_manifest(manifest_path, None)
        result = seal_package(staging, out_dir, case_id, TENANT_ID)
        return result.path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a synthetic Azure Ventra demo package.")
    ap.add_argument("--out", default="tests/fixtures", help="Output directory.")
    ap.add_argument("--case", default="CASE-2026-AZ42")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = generate(out, args.case)
    print(f"Wrote Azure demo package: {path}")
    print(f"  size: {path.stat().st_size:,} bytes")
    print(f"  case_id: {args.case}")
    print(f"  cloud: azure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
