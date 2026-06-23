"""Generate a realistic synthetic Azure/M365 Ventra evidence package for demos and tests.

Techniques are mapped to the Azure Threat Research Matrix (ATRM):
https://microsoft.github.io/Azure-Threat-Research-Matrix/

The data tells one coherent attack story across every Azure collector Ventra ships:

    Recon (AZT101–108) → Initial access via valid credentials + password spray (AZT201–202)
    → malicious OAuth consent (AZT203) → execution on VM/AKS/serverless (AZT301–302)
    → privilege escalation via RBAC/PIM/app roles (AZT401–405) → persistence (AZT501–508)
    → credential access including Key Vault + storage keys (AZT601–605) → impact (AZT701–705)

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
PERSIST_USER = "backup-svc@contoso-demo.com"
BASE = datetime(2026, 6, 7, 2, 14, 0, tzinfo=timezone.utc)

rng = random.Random(4242)

SUB = f"/subscriptions/{SUBSCRIPTION_ID}"
RG = f"{SUB}/resourceGroups/prod-rg"
STORAGE = f"{RG}/providers/Microsoft.Storage/storageAccounts/clientprodblobs"
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/prod-kv"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/web-vm01"
VMSS = f"{RG}/providers/Microsoft.Compute/virtualMachineScaleSets/web-vmss"
AKS = f"{RG}/providers/Microsoft.ContainerService/managedClusters/prod-aks"
FIREWALL = f"{RG}/providers/Microsoft.Network/azureFirewalls/prod-fw"
APPGW = f"{RG}/providers/Microsoft.Network/applicationGateways/prod-appgw"
FRONTDOOR = f"{RG}/providers/Microsoft.Cdn/profiles/prod-fd"
DNS_ZONE = f"{RG}/providers/Microsoft.Network/dnsZones/contoso-demo.com"
NSG = f"{RG}/providers/Microsoft.Network/networkSecurityGroups/prod-nsg"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/prod-vnet"
FUNC = f"{RG}/providers/Microsoft.Web/sites/evil-func"
LOGIC = f"{RG}/providers/Microsoft.Logic/workflows/evil-logic"
AUTO = f"{RG}/providers/Microsoft.Automation/automationAccounts/prod-auto"
VNET_FLOW = f"{VNET}/flowLogs/fl-prod"
NSG_FLOW = f"{NSG}/flowLogs/fl-nsg-prod"


def _t(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _diag(when: str, resource_id: str, category: str, props: dict, **extra) -> dict:
    return {"time": when, "resourceId": resource_id, "category": category,
            "properties": props, **extra}


def build_entra_signin() -> list[dict]:
    """AZT201 Valid Credentials, AZT201.1 User Account, AZT202 Password Spraying."""
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

    # AZT202 — password spray against multiple accounts from attacker IP
    spray_targets = [
        "it.admin@contoso-demo.com",
        "hr.admin@contoso-demo.com",
        "ceo@contoso-demo.com",
        VICTIM_USER,
    ]
    for i, user in enumerate(spray_targets):
        events.append({
            "id": f"spray-fail-{i}",
            "createdDateTime": _t(20 + i * 8),
            "userPrincipalName": user,
            "ipAddress": ATTACKER_IP,
            "appDisplayName": "Microsoft Office",
            "status": {"errorCode": 50126},
            "location": {"countryOrRegion": "RU", "city": "Moscow"},
        })

    # AZT201.1 — successful user sign-in from foreign IP
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
        "id": "sign-attacker-portal",
        "createdDateTime": _t(120),
        "userPrincipalName": VICTIM_USER,
        "ipAddress": ATTACKER_IP,
        "appDisplayName": "Azure Portal",
        "status": {"errorCode": 0},
        "location": {"countryOrRegion": "RU", "city": "Moscow"},
    })
    # AZT201.2 — service principal token acquisition
    events.append({
        "id": "sign-sp-evil",
        "createdDateTime": _t(950),
        "userPrincipalName": MALICIOUS_APP,
        "ipAddress": ATTACKER_IP2,
        "appDisplayName": "Microsoft Azure Management",
        "status": {"errorCode": 0},
        "servicePrincipalId": "sp-evil-666",
    })
    return events


def build_entra_audit() -> list[dict]:
    """AZT104–106, AZT203, AZT401–405, AZT501–502, AZT602–603."""

    def audit(when: str, action: str, target: str, target_type: str = "Application",
              user: str = VICTIM_USER) -> dict:
        return {
            "id": f"audit-{when}-{action[:12]}",
            "activityDateTime": when,
            "activityDisplayName": action,
            "operationType": action.split()[0],
            "initiatedBy": {
                "user": {"userPrincipalName": user, "displayName": user.split("@")[0]},
            },
            "targetResources": [{"displayName": target, "id": target, "type": target_type}],
        }

    return [
        # AZT106.1 — AAD role enumeration
        audit(_t(280), "Get directory role assignments", "DirectoryRole", "DirectoryRole"),
        audit(_t(290), "Get directory role members", "Global Administrator", "DirectoryRole"),
        # AZT104 — user enumeration
        audit(_t(300), "Get user", VICTIM_USER, "User"),
        audit(_t(310), "List users", "Directory", "Directory"),
        # AZT105 / AZT106.2 — application + app role info
        audit(_t(320), "Get application", MALICIOUS_APP),
        audit(_t(330), "Get service principal", MALICIOUS_APP, "ServicePrincipal"),
        audit(_t(340), "Get app role assignments for service principal", MALICIOUS_APP),
        # AZT203 — malicious application consent
        audit(_t(780), "Consent to application", MALICIOUS_APP),
        audit(_t(790), "Add delegated permission grant", MALICIOUS_APP),
        # AZT603 / AZT602 — service principal credential manipulation
        audit(_t(900), "Add service principal credentials", MALICIOUS_APP, "ServicePrincipal"),
        audit(_t(910), "Update application certificate", MALICIOUS_APP),
        # AZT405 — Azure AD application privilege escalation
        audit(_t(960), "Add app role assignment to service principal", MALICIOUS_APP),
        audit(_t(970), "Update application – Required resource access", MALICIOUS_APP),
        audit(_t(980), "Add owner to application", MALICIOUS_APP),
        # AZT401 — PIM role activation
        audit(_t(1000), "Activate role assignment", "Contributor", "Role"),
        # AZT501 — account manipulation
        audit(_t(1100), "Update user", VICTIM_USER, "User"),
        audit(_t(1110), "Reset user password", VICTIM_USER, "User"),
        audit(_t(1120), "Update service principal", MALICIOUS_APP, "ServicePrincipal"),
        # AZT502 — persistence via new accounts
        audit(_t(1130), "Add user", PERSIST_USER, "User"),
        audit(_t(1140), "Add member to role", "Contributor", "Role"),
        audit(_t(1150), "Add service principal", MALICIOUS_APP, "ServicePrincipal"),
        audit(_t(1160), "Invite external user", "attacker-guest@evil.example", "User"),
    ]


def build_activity_log() -> list[dict]:
    """AZT101–108, AZT301–302, AZT402–404, AZT503–508, AZT601–605, AZT701–705."""

    def act(when: str, op: str, caller: str, ip: str, resource: str,
            status: str = "Succeeded") -> dict:
        return {
            "eventTimestamp": when,
            "operationName": {"value": op, "localizedValue": op},
            "status": {"value": status},
            "caller": caller,
            "callerIpAddress": ip,
            "resourceId": resource,
            "subscriptionId": SUBSCRIPTION_ID,
        }

    events = [
        # AZT106.3 / AZT107 — role + resource enumeration
        act(_t(350), "Microsoft.Authorization/roleAssignments/read", VICTIM_USER, ATTACKER_IP,
            f"{SUB}/providers/Microsoft.Authorization/roleAssignments"),
        act(_t(360), "Microsoft.Resources/subscriptions/resources/read", VICTIM_USER, ATTACKER_IP,
            SUB),
        act(_t(370), "Microsoft.Compute/virtualMachines/read", VICTIM_USER, ATTACKER_IP, VM),
        act(_t(380), "Microsoft.Storage/storageAccounts/read", VICTIM_USER, ATTACKER_IP, STORAGE),
        act(_t(390), "Microsoft.KeyVault/vaults/read", VICTIM_USER, ATTACKER_IP, KV),
        # AZT102 — public IP discovery
        act(_t(400), "Microsoft.Network/publicIPAddresses/read", VICTIM_USER, ATTACKER_IP,
            f"{RG}/providers/Microsoft.Network/publicIPAddresses/prod-pip"),
        # AZT103 — public storage exposure check
        act(_t(410), "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            VICTIM_USER, ATTACKER_IP, f"{STORAGE}/blobServices/default/containers"),
        # AZT402 — elevated access toggle
        act(_t(1010), "Microsoft.Authorization/elevatedAccess/read", VICTIM_USER, ATTACKER_IP,
            f"{SUB}/providers/Microsoft.Authorization/elevatedAccess"),
        act(_t(1015), "Microsoft.Authorization/elevatedAccess/write", VICTIM_USER, ATTACKER_IP,
            f"{SUB}/providers/Microsoft.Authorization/elevatedAccess"),
        # RBAC escalation (AZT106.3 / AZT401)
        act(_t(1020), "Microsoft.Authorization/roleAssignments/write", VICTIM_USER, ATTACKER_IP,
            f"{SUB}/providers/Microsoft.Authorization/roleAssignments/ra-evil-001"),
        # AZT605.1 — storage account key dump
        act(_t(1080), "Microsoft.Storage/storageAccounts/listKeys/action", VICTIM_USER,
            ATTACKER_IP2, STORAGE),
        # Defense evasion — diagnostic settings delete
        act(_t(1200), "Microsoft.Insights/diagnosticSettings/delete", VICTIM_USER, ATTACKER_IP2,
            f"{STORAGE}/providers/Microsoft.Insights/diagnosticSettings/storage-logs"),
        # AZT301.1 — VM RunCommand
        act(_t(1260), "Microsoft.Compute/virtualMachines/runCommand/action", VICTIM_USER,
            ATTACKER_IP2, VM),
        # AZT301.2 — CustomScriptExtension
        act(_t(1270), "Microsoft.Compute/virtualMachines/extensions/write", VICTIM_USER,
            ATTACKER_IP2, f"{VM}/extensions/CustomScript"),
        # AZT301.3 — Desired State Configuration
        act(_t(1280), "Microsoft.Compute/virtualMachines/write", VICTIM_USER, ATTACKER_IP2, VM),
        # AZT301.6 — VMSS Run Command
        act(_t(1290), "Microsoft.Compute/virtualMachineScaleSets/runCommand/action", VICTIM_USER,
            ATTACKER_IP2, VMSS),
        # AZT301.5 — AKS command invoke
        act(_t(1300), "Microsoft.ContainerService/managedClusters/runCommand/action", VICTIM_USER,
            ATTACKER_IP2, AKS),
        # AZT301.7 — serial console
        act(_t(1310), "Microsoft.SerialConsole/serialPorts/connect/action", VICTIM_USER,
            ATTACKER_IP2, f"{VM}/serialConsole"),
        # AZT302.4 — Function App execution setup
        act(_t(1320), "Microsoft.Web/sites/functions/write", VICTIM_USER, ATTACKER_IP2, FUNC),
        act(_t(1330), "Microsoft.Web/sites/host/listKeys/action", VICTIM_USER, ATTACKER_IP2, FUNC),
        # AZT302 — Automation runbook
        act(_t(1340), "Microsoft.Automation/automationAccounts/runbooks/write", VICTIM_USER,
            ATTACKER_IP2, f"{AUTO}/runbooks/evil-runbook"),
        act(_t(1350), "Microsoft.Automation/automationAccounts/jobs/write", VICTIM_USER,
            ATTACKER_IP2, f"{AUTO}/jobs/job-evil-001"),
        # AZT404.1 — Function app impersonation
        act(_t(1360), "Microsoft.Web/sites/config/list/action", VICTIM_USER, ATTACKER_IP2, FUNC),
        # AZT404.2 — Logic app impersonation
        act(_t(1370), "Microsoft.Logic/workflows/run/action", VICTIM_USER, ATTACKER_IP2, LOGIC),
        # AZT503 — HTTP trigger persistence
        act(_t(1380), "Microsoft.Web/sites/functions/list/action", VICTIM_USER, ATTACKER_IP2, FUNC),
        act(_t(1390), "Microsoft.Logic/workflows/triggers/list/action", VICTIM_USER, ATTACKER_IP2,
            LOGIC),
        # AZT504 — watcher task
        act(_t(1400), "Microsoft.Automation/automationAccounts/watchers/write", VICTIM_USER,
            ATTACKER_IP2, f"{AUTO}/watchers/evil-watcher"),
        # AZT505 — scheduled job
        act(_t(1410), "Microsoft.Logic/workflows/write", VICTIM_USER, ATTACKER_IP2, LOGIC),
        # AZT506 — NSG modification
        act(_t(1420), "Microsoft.Network/networkSecurityGroups/securityRules/write", VICTIM_USER,
            ATTACKER_IP2, f"{NSG}/securityRules/AllowAttacker"),
        # AZT507.1 — Azure Lighthouse delegation
        act(_t(1430), "Microsoft.ManagedServices/registrationDefinitions/write", VICTIM_USER,
            ATTACKER_IP2, f"{SUB}/providers/Microsoft.ManagedServices/registrationDefinitions"),
        # AZT508 — Azure Policy assignment
        act(_t(1440), "Microsoft.Authorization/policyAssignments/write", VICTIM_USER,
            ATTACKER_IP2, f"{SUB}/providers/Microsoft.Authorization/policyAssignments/evil"),
        # AZT605.3 — deployment history secret reveal
        act(_t(1450), "Microsoft.Resources/deployments/read", VICTIM_USER, ATTACKER_IP2,
            f"{RG}/providers/Microsoft.Resources/deployments/deploy-secrets"),
        # Blob reads (credential access / staging)
        act(_t(1460), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            VICTIM_USER, ATTACKER_IP2,
            f"{STORAGE}/blobServices/default/containers/backups/blobs/customer-export-1.csv"),
        act(_t(1470), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            VICTIM_USER, ATTACKER_IP2,
            f"{STORAGE}/blobServices/default/containers/backups/blobs/customer-export-2.csv"),
        # AZT701 — SAS URI generation
        act(_t(1800), "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationSas/action",
            VICTIM_USER, ATTACKER_IP2, STORAGE),
        act(_t(1810), "Microsoft.Compute/disks/beginGetAccess/action", VICTIM_USER, ATTACKER_IP2,
            f"{RG}/providers/Microsoft.Compute/disks/web-vm01-osdisk"),
        # AZT702 — file share mount
        act(_t(1820), "Microsoft.Storage/storageAccounts/fileServices/shares/read", VICTIM_USER,
            ATTACKER_IP2, f"{STORAGE}/fileServices/default/shares/backups"),
        # AZT703 — replication
        act(_t(1830), "Microsoft.Storage/storageAccounts/objectReplicationPolicies/write",
            VICTIM_USER, ATTACKER_IP2, STORAGE),
        # AZT704 — soft-delete recovery
        act(_t(1840), "Microsoft.KeyVault/vaults/deletedSecrets/recover/action", VICTIM_USER,
            ATTACKER_IP2, f"{KV}/deletedSecrets/db-password"),
        act(_t(1850), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/restore/action",
            VICTIM_USER, ATTACKER_IP2,
            f"{STORAGE}/blobServices/default/containers/backups/blobs/deleted-export.csv"),
        act(_t(1860), "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/"
            "protectedItems/recover/action", VICTIM_USER, ATTACKER_IP2,
            f"{RG}/providers/Microsoft.RecoveryServices/vaults/prod-rsv"),
        # AZT705 — backup delete
        act(_t(1870), "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/"
            "protectedItems/delete", VICTIM_USER, ATTACKER_IP2,
            f"{RG}/providers/Microsoft.RecoveryServices/vaults/prod-rsv/backupFabrics/"
            f"Azure/protectionContainers/iaasvm;iaasvm;web-vm01"),
    ]
    return events


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
                "alertDisplayName": "Password spray against multiple accounts",
                "severity": "Medium",
                "startTimeUtc": _t(40),
                "compromisedEntity": TENANT_NAME,
                "alertType": "PasswordSpray",
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
                "alertDisplayName": "Suspicious Run Command on virtual machine",
                "severity": "High",
                "startTimeUtc": _t(1270),
                "compromisedEntity": "web-vm01",
                "alertType": "SuspiciousCommandExecution",
                "resourceLocation": REGION,
            },
            "_ventra_subscription_id": SUBSCRIPTION_ID,
        },
        {
            "properties": {
                "alertDisplayName": "Anomalous Key Vault secret access",
                "severity": "High",
                "startTimeUtc": _t(1250),
                "compromisedEntity": "prod-kv",
                "alertType": "KeyVaultAnomaly",
                "resourceLocation": REGION,
            },
            "_ventra_subscription_id": SUBSCRIPTION_ID,
        },
        {
            "properties": {
                "alertDisplayName": "Anomalous blob read volume",
                "severity": "Medium",
                "startTimeUtc": _t(1500),
                "compromisedEntity": "clientprodblobs",
                "alertType": "StorageAnomaly",
                "resourceLocation": REGION,
            },
            "_ventra_subscription_id": SUBSCRIPTION_ID,
        },
        {
            "properties": {
                "alertDisplayName": "Azure Backup deletion detected",
                "severity": "High",
                "startTimeUtc": _t(1880),
                "compromisedEntity": "prod-rsv",
                "alertType": "BackupDeletion",
                "resourceLocation": REGION,
            },
            "_ventra_subscription_id": SUBSCRIPTION_ID,
        },
    ]


def _flow_record(src: str, dst: str, dport: int, action: str, nbytes: int,
                 when: str, resource_id: str) -> dict:
    return {
        "srcaddr": src,
        "dstaddr": dst,
        "dstport": dport,
        "action": action,
        "bytes": nbytes,
        "timestamp": when,
        "resource_id": resource_id,
        "_ventra_region": REGION,
    }


def build_vnet_flow() -> list[dict]:
    """AZT101 port mapping + exfil egress (AZT701 staging)."""
    out: list[dict] = []
    for i in range(15):
        out.append(_flow_record("10.0.2.4", "10.0.3.10", 443, "ALLOW",
                                rng.randint(500, 8000), _t(800 + i * 30), VNET_FLOW))
    # AZT101 — port scan probes (denied)
    for i, port in enumerate([22, 3389, 445, 1433, 5985, 8080, 8443]):
        out.append(_flow_record(ATTACKER_IP, "10.0.1.5", port, "DENY",
                                rng.randint(40, 200), _t(200 + i * 15), VNET_FLOW))
    # Large egress exfil
    for i in range(10):
        out.append(_flow_record("10.0.2.4", EXFIL_IP, 443, "ALLOW",
                                rng.randint(5_000_000, 12_000_000), _t(1500 + i * 45),
                                VNET_FLOW))
    return out


def build_nsg_flow() -> list[dict]:
    """AZT101 / AZT506 — legacy NSG flow logs (same flat shape as vnet_flow)."""
    out: list[dict] = []
    for i in range(12):
        out.append(_flow_record("10.0.2.4", "10.0.3.10", 443, "ALLOW",
                                rng.randint(500, 8000), _t(820 + i * 25), NSG_FLOW))
    for i, port in enumerate([22, 3389, 445, 5985]):
        out.append(_flow_record(ATTACKER_IP, "10.0.1.5", port, "DENY",
                                rng.randint(40, 200), _t(210 + i * 18), NSG_FLOW))
    for i in range(6):
        out.append(_flow_record("10.0.2.4", EXFIL_IP, 443, "ALLOW",
                                rng.randint(3_000_000, 8_000_000), _t(1520 + i * 40),
                                NSG_FLOW))
    return out


def build_unified_audit() -> list[dict]:
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
            "CreationTime": _t(900),
            "Operation": "Add service principal credentials.",
            "Workload": "AzureActiveDirectory",
            "UserId": VICTIM_USER,
            "ClientIP": ATTACKER_IP,
            "ResultStatus": "Success",
            "ObjectId": MALICIOUS_APP_ID,
            "OrganizationId": TENANT_ID,
        },
        {
            "CreationTime": _t(1130),
            "Operation": "Add user.",
            "Workload": "AzureActiveDirectory",
            "UserId": VICTIM_USER,
            "ClientIP": ATTACKER_IP2,
            "ResultStatus": "Success",
            "ObjectId": PERSIST_USER,
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
    ]


def build_unified_audit_search() -> list[dict]:
    return [
        {
            "CreationTime": _t(1500),
            "UserId": VICTIM_USER,
            "Operation": "MailItemsAccessed",
            "RecordType": 2,
            "ClientIP": ATTACKER_IP2,
            "ResultStatus": "Succeeded",
            "Workload": "Exchange",
            "OrganizationId": TENANT_ID,
            "ObjectId": "mbx-finance-001",
        },
        {
            "CreationTime": _t(2400),
            "UserId": VICTIM_USER,
            "Operation": "FileDownloaded",
            "RecordType": 6,
            "ClientIP": ATTACKER_IP,
            "ResultStatus": "Succeeded",
            "Workload": "SharePoint",
            "OrganizationId": TENANT_ID,
            "ObjectId": "https://contoso.sharepoint.com/sites/finance/export.zip",
        },
    ]


def build_log_analytics() -> list[dict]:
    la_ws = (f"{RG}/providers/Microsoft.OperationalInsights/workspaces/prod-la")
    return [
        {
            "TimeGenerated": _t(1700),
            "ResourceId": APPGW,
            "Category": "ApplicationGatewayAccessLog",
            "clientIP_s": ATTACKER_IP,
            "httpMethod_s": "GET",
            "requestUri_s": "/finance/export.csv",
            "httpStatus_d": 200,
            "_ventra_la_source": "app_gateway",
            "_ventra_la_workspace": la_ws,
        },
        {
            "TimeGenerated": _t(1710),
            "ResourceId": APPGW,
            "Category": "ApplicationGatewayFirewallLog",
            "clientIP_s": ATTACKER_IP,
            "action_s": "BLOCK",
            "ruleId_s": "942100",
            "_ventra_la_source": "app_gateway",
            "_ventra_la_workspace": la_ws,
        },
    ]


def build_app_gateway() -> list[dict]:
    return [
        _diag(_t(1700), APPGW, "ApplicationGatewayAccessLog", {
            "clientIP": ATTACKER_IP,
            "httpMethod": "GET",
            "requestUri": "/finance/export.csv",
            "httpStatus": 200,
        }),
        _diag(_t(1710), APPGW, "ApplicationGatewayFirewallLog", {
            "clientIP": ATTACKER_IP,
            "action": "BLOCK",
            "ruleId": "942100",
            "requestUri": "/finance/export.csv?cmd=whoami",
        }),
        _diag(_t(1720), APPGW, "ApplicationGatewayPerformanceLog", {
            "timeTaken": 42,
            "backendPool": "prod-backend",
        }),
    ]


def build_front_door() -> list[dict]:
    return [
        _diag(_t(1730), FRONTDOOR, "FrontDoorAccessLog", {
            "clientIp": ATTACKER_IP,
            "requestMethod": "GET",
            "requestUri": "https://portal.contoso-demo.com/admin",
            "httpStatusCode": 200,
        }),
        _diag(_t(1740), FRONTDOOR, "FrontDoorWebApplicationFirewallLog", {
            "clientIp": ATTACKER_IP2,
            "action": "Block",
            "requestUri": "https://portal.contoso-demo.com/?q=<script>",
            "ruleName": "XSS-001",
        }),
    ]


def build_dns() -> list[dict]:
    """AZT102 IP discovery via DNS recon."""
    queries = [
        ("contoso-demo.com", "A", "NOERROR"),
        ("internal.contoso-demo.com", "A", "NOERROR"),
        ("prod-db.contoso-demo.com", "A", "NXDOMAIN"),
        ("login.microsoftonline.com", "A", "NOERROR"),
        ("evil-c2.example", "A", "NXDOMAIN"),
    ]
    out: list[dict] = []
    for i, (qname, qtype, rcode) in enumerate(queries):
        out.append(_diag(_t(250 + i * 20), DNS_ZONE, "QueryLogs", {
            "QueryName": qname,
            "QueryType": qtype,
            "ResponseCode": rcode,
            "SourceIp": ATTACKER_IP,
        }))
    return out


def build_azure_firewall() -> list[dict]:
    return [
        _diag(_t(220), FIREWALL, "AzureFirewallNetworkRule", {
            "msg": "Deny inbound SSH probe",
            "srcIp": ATTACKER_IP,
            "destIp": "10.0.1.5",
            "action": "Deny",
        }),
        _diag(_t(1550), FIREWALL, "AzureFirewallApplicationRule", {
            "msg": "Allow HTTPS egress",
            "srcIp": "10.0.2.4",
            "destIp": EXFIL_IP,
            "action": "Allow",
        }),
        _diag(_t(1560), FIREWALL, "AzureFirewallDnsProxy", {
            "msg": "DNS query to suspicious domain",
            "srcIp": "10.0.2.4",
            "destIp": "8.8.8.8",
            "action": "Alert",
        }),
    ]


def build_key_vault() -> list[dict]:
    """AZT604 Key Vault dumping."""
    ops = [
        ("SecretGet", "db-connection-string"),
        ("SecretList", ""),
        ("CertificateGet", "tls-wildcard"),
        ("KeyGet", "encryption-key-01"),
    ]
    out: list[dict] = []
    for i, (op, target) in enumerate(ops):
        out.append(_diag(_t(1220 + i * 15), KV, "AuditEvent", {
            "operationName": op,
            "callerIpAddress": ATTACKER_IP2,
            "identity": {"claim": {"upn": VICTIM_USER}},
            "resultSignature": "OK",
            "id": target,
        }))
    return out


def build_aks_audit() -> list[dict]:
    """AZT301.5 AKS command invoke + AZT601.2 IMDS token theft from pod."""
    return [
        {
            "stage": "ResponseComplete",
            "verb": "create",
            "user": {"username": "system:serviceaccount:default:attacker-sa"},
            "sourceIPs": ["10.0.2.4"],
            "objectRef": {
                "resource": "pods",
                "subresource": "exec",
                "namespace": "prod",
                "name": "web-01",
            },
            "responseStatus": {"code": 201},
            "stageTimestamp": _t(1305),
            "requestReceivedTimestamp": _t(1304),
            "_ventra_cluster": "prod-aks",
            "_ventra_resource_id": AKS,
        },
        {
            "stage": "ResponseComplete",
            "verb": "get",
            "user": {"username": "system:serviceaccount:default:attacker-sa"},
            "sourceIPs": ["10.0.2.4"],
            "objectRef": {"resource": "secrets", "namespace": "prod", "name": "db-creds"},
            "responseStatus": {"code": 200},
            "stageTimestamp": _t(1315),
            "requestReceivedTimestamp": _t(1314),
            "_ventra_cluster": "prod-aks",
            "_ventra_resource_id": AKS,
        },
        {
            "stage": "ResponseComplete",
            "verb": "create",
            "user": {"username": "system:serviceaccount:kube-system:aks-imds-client"},
            "sourceIPs": ["10.0.2.4"],
            "objectRef": {"resource": "pods", "namespace": "kube-system", "name": "imds-probe"},
            "responseStatus": {"code": 201},
            "stageTimestamp": _t(1325),
            "requestReceivedTimestamp": _t(1324),
            "_ventra_cluster": "prod-aks",
            "_ventra_resource_id": AKS,
        },
    ]


def build_oauth_consent() -> list[dict]:
    return [{
        "clientId": MALICIOUS_APP_ID,
        "principalId": VICTIM_USER,
        "consentType": "Principal",
        "scope": "Mail.Read Mail.Send Files.ReadWrite.All Directory.Read.All",
        "resourceId": "00000003-0000-0000-c000-000000000000",
    }]


def build_storage_access() -> list[dict]:
    """AZT605.1 storage key usage + blob exfil."""
    out: list[dict] = []
    for i in range(12):
        out.append({
            "time": _t(1460 + i * 35),
            "resourceId": STORAGE,
            "category": "StorageRead",
            "properties": {
                "operationName": "GetBlob",
                "uri": f"https://clientprodblobs.blob.core.windows.net/backups/customer-export-{i}.csv",
                "callerIpAddress": ATTACKER_IP2,
                "authenticationType": "AccountKey" if i < 3 else "OAuth",
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
            {"id": "u-persist", "userPrincipalName": PERSIST_USER,
             "displayName": "Backup Service", "accountEnabled": True},
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
            {"roleName": "User Access Administrator", "roleType": "BuiltInRole",
             "_ventra_subscription_id": SUBSCRIPTION_ID},
        ],
        "role_assignments": [
            {"principalId": "u-finance", "roleDefinitionName": "Reader",
             "scope": SUB, "_ventra_subscription_id": SUBSCRIPTION_ID},
            {"principalId": "sp-evil-666", "roleDefinitionName": "Contributor",
             "scope": SUB, "_ventra_subscription_id": SUBSCRIPTION_ID, "createdOn": _t(1020)},
            {"principalId": "sp-evil-666", "roleDefinitionName": "User Access Administrator",
             "scope": SUB, "_ventra_subscription_id": SUBSCRIPTION_ID, "createdOn": _t(1025)},
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
    resources = [
        {"id": STORAGE, "name": "clientprodblobs",
         "type": "Microsoft.Storage/storageAccounts", "location": REGION,
         "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": VNET, "name": "prod-vnet", "type": "Microsoft.Network/virtualNetworks",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": VM, "name": "web-vm01", "type": "Microsoft.Compute/virtualMachines",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": AKS, "name": "prod-aks", "type": "Microsoft.ContainerService/managedClusters",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": KV, "name": "prod-kv", "type": "Microsoft.KeyVault/vaults",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": FIREWALL, "name": "prod-fw", "type": "Microsoft.Network/azureFirewalls",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": APPGW, "name": "prod-appgw", "type": "Microsoft.Network/applicationGateways",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": FRONTDOOR, "name": "prod-fd", "type": "Microsoft.Cdn/profiles",
         "location": "global", "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": DNS_ZONE, "name": "contoso-demo.com", "type": "Microsoft.Network/dnsZones",
         "location": "global", "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": NSG, "name": "prod-nsg", "type": "Microsoft.Network/networkSecurityGroups",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": FUNC, "name": "evil-func", "type": "Microsoft.Web/sites",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
        {"id": LOGIC, "name": "evil-logic", "type": "Microsoft.Logic/workflows",
         "location": REGION, "resourceGroup": "prod-rg", "subscriptionId": SUBSCRIPTION_ID},
    ]
    return {"subscriptions": [SUBSCRIPTION_ID], "resources": resources}


def build_diag_posture() -> dict:
    """All diagnostic sources routed — demo exercises every collector."""
    return {
        "app_gateway": {
            "resources_total": 1, "routed_to_storage": 1, "log_analytics_only": 0,
            "event_hub_only": 0, "no_routing": 0, "sample": ["prod-appgw:storage"],
        },
        "front_door": {
            "resources_total": 1, "routed_to_storage": 1, "log_analytics_only": 0,
            "event_hub_only": 0, "no_routing": 0, "sample": ["prod-fd:storage"],
        },
        "dns": {
            "resources_total": 1, "routed_to_storage": 1, "log_analytics_only": 0,
            "event_hub_only": 0, "no_routing": 0, "sample": ["contoso-demo.com:storage"],
        },
        "storage_access": {
            "resources_total": 1, "routed_to_storage": 1, "log_analytics_only": 0,
            "event_hub_only": 0, "no_routing": 0, "sample": ["clientprodblobs:storage"],
        },
        "key_vault": {
            "resources_total": 1, "routed_to_storage": 1, "log_analytics_only": 0,
            "event_hub_only": 0, "no_routing": 0, "sample": ["prod-kv:storage"],
        },
        "aks_audit": {
            "resources_total": 1, "routed_to_storage": 1, "log_analytics_only": 0,
            "event_hub_only": 0, "no_routing": 0, "sample": ["prod-aks:kube-audit"],
        },
        "azure_firewall": {
            "resources_total": 1, "routed_to_storage": 1, "log_analytics_only": 0,
            "event_hub_only": 0, "no_routing": 0, "sample": ["prod-fw:storage"],
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
                principal_arn="azure-sp:sp-ventra-collector-demo",
                user_id=TENANT_ID, source_ip="100.64.0.10"),
            started_at=_t(-10), completed_at=_t(2500),
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

        entra_signin = build_entra_signin()
        entra_audit = build_entra_audit()
        activity_log = build_activity_log()
        defender = build_defender()
        vnet_flow = build_vnet_flow()
        nsg_flow = build_nsg_flow()
        unified_audit = build_unified_audit()
        unified_audit_search = build_unified_audit_search()
        oauth = build_oauth_consent()
        storage_access = build_storage_access()
        log_analytics = build_log_analytics()
        app_gateway = build_app_gateway()
        front_door = build_front_door()
        dns = build_dns()
        azure_firewall = build_azure_firewall()
        key_vault = build_key_vault()
        aks_audit = build_aks_audit()

        src("subscription", [("snapshot.json", _write_json(
            sd / "subscription/snapshot.json", build_subscription_snapshot()))],
            notes="Tenant + subscription context.")
        src("entra_signin", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "entra_signin/events.jsonl.gz",
                                                entra_signin)),
            ("_meta.json", _write_json(sd / "entra_signin/_meta.json",
                                        {"source": "entra_signin", "records": len(entra_signin)})),
        ], notes="Sign-in logs: valid creds, password spray, SP auth (ATRM AZT201–202).")
        src("entra_audit", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "entra_audit/events.jsonl.gz", entra_audit)),
            ("_meta.json", _write_json(sd / "entra_audit/_meta.json",
                                        {"source": "entra_audit", "records": len(entra_audit)})),
        ], notes="Directory audit: recon, consent, persistence (ATRM AZT104–508).")
        src("activity_log", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "activity_log/events.jsonl.gz",
                                                 activity_log)),
            ("_meta.json", _write_json(sd / "activity_log/_meta.json",
                                        {"source": "activity_log", "records": len(activity_log)})),
        ], notes="Activity Log: execution, escalation, impact (ATRM AZT301–705).")
        src("defender", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "defender/events.jsonl.gz", defender)),
            ("config.json", _write_json(sd / "defender/config.json",
                                         {"subscriptions": [{"subscription_id": SUBSCRIPTION_ID,
                                                             "alerts": len(defender)}]})),
        ], notes=f"{len(defender)} Defender alerts across the attack chain.")
        src("vnet_flow", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "vnet_flow/events.jsonl.gz", vnet_flow)),
            ("config.json", _write_json(sd / "vnet_flow/config.json", {
                "flow_logs": [{"name": "fl-prod", "target": "prod-vnet", "enabled": True}],
            })),
        ], notes="VNet flow: port scan + exfil (ATRM AZT101).")
        src("nsg_flow", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "nsg_flow/events.jsonl.gz", nsg_flow)),
            ("config.json", _write_json(sd / "nsg_flow/config.json", {
                "flow_logs": [{"name": "fl-nsg-prod", "target": "prod-nsg", "enabled": True}],
            })),
        ], notes="NSG flow (legacy): port scan + exfil (ATRM AZT101/506).")
        src("unified_audit", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "unified_audit/events.jsonl.gz",
                                                unified_audit)),
            ("_meta.json", _write_json(sd / "unified_audit/_meta.json",
                                        {"source": "unified_audit", "records": len(unified_audit)})),
        ], notes="UAL: consent, persistence, mailbox access (ATRM AZT203/502).")
        src("unified_audit_search", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "unified_audit_search/events.jsonl.gz",
                                                unified_audit_search)),
            ("_meta.json", _write_json(sd / "unified_audit_search/_meta.json",
                                        {"source": "unified_audit_search",
                                         "records": len(unified_audit_search)})),
        ], notes="Search-UnifiedAuditLog: mail + SharePoint access.")
        src("oauth_consent", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "oauth_consent/events.jsonl.gz", oauth)),
            ("_meta.json", _write_json(sd / "oauth_consent/_meta.json",
                                        {"source": "oauth_consent", "records": len(oauth)})),
        ], notes="Illicit OAuth permission grant (ATRM AZT203).")
        src("storage_access", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "storage_access/events.jsonl.gz",
                                               storage_access)),
        ], notes="Blob reads via account key + OAuth (ATRM AZT605).")
        src("log_analytics", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "log_analytics/events.jsonl.gz",
                                                log_analytics)),
            ("_meta.json", _write_json(sd / "log_analytics/_meta.json",
                                        {"source": "log_analytics", "records": len(log_analytics)})),
        ], notes="App Gateway access + WAF from Log Analytics workspace.")
        src("app_gateway", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "app_gateway/events.jsonl.gz", app_gateway)),
        ], notes="App Gateway access + WAF from Storage diagnostics.")
        src("front_door", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "front_door/events.jsonl.gz", front_door)),
        ], notes="Front Door access + WAF (ATRM AZT503).")
        src("dns", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "dns/events.jsonl.gz", dns)),
        ], notes="DNS query recon (ATRM AZT102).")
        src("azure_firewall", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "azure_firewall/events.jsonl.gz",
                                                 azure_firewall)),
        ], notes="Azure Firewall network/app/DNS logs (ATRM AZT101).")
        src("key_vault", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "key_vault/events.jsonl.gz", key_vault)),
        ], notes="Key Vault secret/cert/key access (ATRM AZT604).")
        src("aks_audit", [
            ("events.jsonl.gz", _write_gz_jsonl(sd / "aks_audit/events.jsonl.gz", aks_audit)),
            ("config.json", _write_json(sd / "aks_audit/config.json", {
                "clusters": [{"name": "prod-aks", "id": AKS, "audit_routed": True}],
                "audit_enabled_count": 1,
                "audit_disabled_count": 0,
            })),
        ], notes="AKS kube-audit: exec + secret read + IMDS probe (ATRM AZT301.5/601.2).")
        src("entra_directory", [("snapshot.json", _write_json(
            sd / "entra_directory/snapshot.json", build_entra_directory_snapshot()))],
            notes="Users, apps, malicious service principal (ATRM AZT104–105).")
        src("rbac", [("snapshot.json", _write_json(
            sd / "rbac/snapshot.json", build_rbac_snapshot()))],
            notes="Contributor + UAA on malicious SP (ATRM AZT106.3/401).")
        src("resource_graph", [("snapshot.json", _write_json(
            sd / "resource_graph/snapshot.json", build_resource_graph_snapshot()))],
            notes="ARM inventory snapshot (ATRM AZT107).")
        src("diag_posture", [("config.json", _write_json(
            sd / "diag_posture/config.json", build_diag_posture()))],
            notes="All diagnostic sources routed to Storage — full collector coverage.")

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
