#!/usr/bin/env python3
"""Copy cloud service icons into console/frontend/public/icons/."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ICON_SRC = REPO / "icons"
OUT = REPO / "console" / "frontend" / "public" / "icons"

AWS_ZIP = ICON_SRC / "Icon-package_04302026.4705b90f5aa45b019271a2699e9ce9b97b941ee1.zip"
AZURE_ZIP = ICON_SRC / "Azure_Public_Service_Icons_V23.zip"
GCP_ZIP = ICON_SRC / "png-512.zip"

AWS = {
    "account": ("account", "Architecture-Group-Icons_04302026/Virtual-private-cloud-VPC_32.png"),
    "cloudfront": ("cloudfront access logs", "Architecture-Service-Icons_04302026/Arch_Networking-Content-Delivery/64/Arch_Amazon-CloudFront_64.png"),
    "cloudtrail": ("cloudtrail", "Architecture-Service-Icons_04302026/Arch_Management-Tools/64/Arch_AWS-CloudTrail_64.png"),
    "config": ("config", "Architecture-Service-Icons_04302026/Arch_Management-Tools/64/Arch_AWS-Config_64.png"),
    "detective": ("detective", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_Amazon-Detective_64.png"),
    "ec2": ("ec2", "Architecture-Service-Icons_04302026/Arch_Compute/64/Arch_Amazon-EC2_64.png"),
    "eks_audit": ("eks audit", "Architecture-Service-Icons_04302026/Arch_Containers/64/Arch_Amazon-Elastic-Kubernetes-Service_64.png"),
    "elb_alb": ("elb alb access logs", "Architecture-Service-Icons_04302026/Arch_Networking-Content-Delivery/64/Arch_Elastic-Load-Balancing_64.png"),
    "guardduty": ("guardduty", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_Amazon-GuardDuty_64.png"),
    "iam": ("iam", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_AWS-Identity-and-Access-Management_64.png"),
    "inspector2": ("inspector2", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_Amazon-Inspector_64.png"),
    "kms": ("kms", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_AWS-Key-Management-Service_64.png"),
    "lambda": ("lambda", "Architecture-Service-Icons_04302026/Arch_Compute/64/Arch_AWS-Lambda_64.png"),
    "log_posture": ("log posture", "Architecture-Service-Icons_04302026/Arch_Management-Tools/64/Arch_AWS-CloudTrail_64.png"),
    "macie": ("macie", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_Amazon-Macie_64.png"),
    "route53_resolver": ("route53 resolver", "Architecture-Service-Icons_04302026/Arch_Networking-Content-Delivery/64/Arch_Amazon-Route-53_64.png"),
    "s3": ("s3", "Architecture-Service-Icons_04302026/Arch_Storage/64/Arch_Amazon-Simple-Storage-Service_64.png"),
    "s3_access": ("s3 access logs", "Architecture-Service-Icons_04302026/Arch_Storage/64/Arch_Amazon-Simple-Storage-Service_64.png"),
    "secrets": ("secrets", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_AWS-Secrets-Manager_64.png"),
    "securityhub": ("security hub", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_AWS-Security-Hub_64.png"),
    "vpc_flow": ("vpc flow logs", "Architecture-Group-Icons_04302026/Virtual-private-cloud-VPC_32.png"),
    "waf": ("waf", "Architecture-Service-Icons_04302026/Arch_Security-Identity/64/Arch_AWS-WAF_64.png"),
}

AZURE = {
    "activity_log": ("activity log", "Azure_Public_Service_Icons/Icons/monitor/00007-icon-service-Activity-Log.svg"),
    "aks_audit": ("aks audit", "Azure_Public_Service_Icons/Icons/containers/10023-icon-service-Kubernetes-Services.svg"),
    "app_gateway": ("app gateway access logs", "Azure_Public_Service_Icons/Icons/networking/10073-icon-service-Front-Door-and-CDN-Profiles.svg"),
    "azure_firewall": ("azure firewall logs", "Azure_Public_Service_Icons/Icons/networking/10084-icon-service-Firewalls.svg"),
    "defender": ("defender", "Azure_Public_Service_Icons/Icons/security/10248-icon-service-Microsoft-Defender-for-Cloud.svg"),
    "diag_posture": ("diagnostic posture", "Azure_Public_Service_Icons/Icons/monitor/00009-icon-service-Log-Analytics-Workspaces.svg"),
    "dns": ("dns", "Azure_Public_Service_Icons/Icons/networking/10064-icon-service-DNS-Zones.svg"),
    "entra_audit": ("entra audit", "Azure_Public_Service_Icons/Icons/identity/10230-icon-service-Microsoft-Entra-ID.svg"),
    "entra_directory": ("entra directory", "Azure_Public_Service_Icons/Icons/identity/10230-icon-service-Microsoft-Entra-ID.svg"),
    "entra_signin": ("entra signin", "Azure_Public_Service_Icons/Icons/identity/10230-icon-service-Microsoft-Entra-ID.svg"),
    "front_door": ("front door access logs", "Azure_Public_Service_Icons/Icons/networking/10073-icon-service-Front-Door-and-CDN-Profiles.svg"),
    "key_vault": ("key vault", "Azure_Public_Service_Icons/Icons/security/10245-icon-service-Key-Vaults.svg"),
    "log_analytics": ("log analytics", "Azure_Public_Service_Icons/Icons/analytics/00009-icon-service-Log-Analytics-Workspaces.svg"),
    "nsg_flow": ("nsg flow logs", "Azure_Public_Service_Icons/Icons/networking/10061-icon-service-Virtual-Networks.svg"),
    "oauth_consent": ("oauth consent", "Azure_Public_Service_Icons/Icons/identity/10230-icon-service-Microsoft-Entra-ID.svg"),
    "rbac": ("rbac", "Azure_Public_Service_Icons/Icons/identity/10232-icon-service-Azure-RBAC.svg"),
    "resource_graph": ("resource graph", "Azure_Public_Service_Icons/Icons/general/10002-icon-service-All-Resources.svg"),
    "storage_access": ("storage access logs", "Azure_Public_Service_Icons/Icons/storage/10086-icon-service-Storage-Accounts.svg"),
    "subscription": ("subscription", "Azure_Public_Service_Icons/Icons/general/10002-icon-service-All-Resources.svg"),
    "unified_audit": ("unified audit", "Azure_Public_Service_Icons/Icons/other/10779-icon-service-Microsoft-365.svg"),
    "unified_audit_search": ("unified audit search", "Azure_Public_Service_Icons/Icons/other/10779-icon-service-Microsoft-365.svg"),
    "vnet_flow": ("vnet flow logs", "Azure_Public_Service_Icons/Icons/networking/10061-icon-service-Virtual-Networks.svg"),
}

GCP = {
    "api_gateway": ("api gateway", "png-512/API.png"),
    "cloud_audit_admin": ("cloud audit admin", "png-512/Cloud-Audit-Logs.png"),
    "cloud_audit_data": ("cloud audit data", "png-512/Cloud-Audit-Logs.png"),
    "cloud_audit_system": ("cloud audit system", "png-512/Cloud-Audit-Logs.png"),
    "cloud_functions": ("cloud functions", "png-512/Cloud-Functions.png"),
    "cloud_monitoring": ("cloud monitoring", "png-512/Cloud-Monitoring.png"),
    "firewall_logs": ("firewall logs", "png-512/Cloud-Firewall-Rules.png"),
    "iam_policy": ("iam policy", "png-512/Identity-and-Access-Management.png"),
    "load_balancer": ("load balancer access logs", "png-512/Cloud-Load-Balancing.png"),
    "login_events": ("login events", "png-512/Cloud-Logging.png"),
    "project": ("project", "png-512/Cloud-Resource-Manager.png"),
    "scc_findings": ("scc findings", "png-512/Security-Command-Center.png"),
    "storage_access": ("storage access logs", "png-512/Cloud-Storage.png"),
    "vm_logs": ("vm logs", "png-512/Compute-Engine.png"),
    "vpc_flow": ("vpc flow logs", "png-512/Virtual-Private-Cloud.png"),
    "workspace_audit": ("workspace audit", "png-512/Cloud-Logging.png"),
}

def _extract(zip_path, member, dest):
    with zipfile.ZipFile(zip_path) as zf:
        if member not in zf.namelist():
            tail = member.split("/")[-1]
            matches = [n for n in zf.namelist() if tail in n]
            if not matches:
                raise KeyError(member)
            member = matches[0]
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, dest.open("wb") as out:
            shutil.copyfileobj(src, out)

def main():
    if OUT.is_dir():
        shutil.rmtree(OUT)
    missing = []
    for cloud, (mapping, zip_path) in {
        "aws": (AWS, AWS_ZIP),
        "azure": (AZURE, AZURE_ZIP),
        "gcp": (GCP, GCP_ZIP),
    }.items():
        for collector, (label, member) in mapping.items():
            ext = Path(member).suffix or ".png"
            dest = OUT / cloud / f"{label}{ext}"
            try:
                _extract(zip_path, member, dest)
            except Exception as exc:
                missing.append(f"{cloud}/{collector}: {exc}")
    print(f"Wrote icons to {OUT}")
    if missing:
        for line in missing:
            print("MISSING", line)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
