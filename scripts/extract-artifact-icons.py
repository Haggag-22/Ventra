#!/usr/bin/env python3
"""Copy cloud service SVGs into console/frontend/public/icons/."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ICON_SRC = REPO / "icons"
OUT = REPO / "console" / "frontend" / "public" / "icons"
LOGOS_OUT = REPO / "console" / "frontend" / "public" / "logos"

AWS_ROOT = ICON_SRC / "AWS Icons"
AZURE_ROOT = ICON_SRC / "Azure Icons" / "Icons"
GCP_ROOT = ICON_SRC / "GCP Icons"
K8S_ROOT = ICON_SRC / "Kubernetes Icons"

# collector -> source filename (looked up under the provider tree)
AWS = {
    "account": "Organizations.svg",
    "apigateway": "API-Gateway.svg",
    "cloudfront": "CloudFront.svg",
    "cloudtrail": "CloudTrail.svg",
    "cloudwatch": "CloudWatch.svg",
    "config": "Config.svg",
    "detective": "Detective.svg",
    "dynamodb_streams": "DynamoDB.svg",
    "ec2": "EC2.svg",
    "eks_audit": "Elastic-Kubernetes-Service.svg",
    "elb_alb": "Elastic-Load-Balancing.svg",
    "guardduty": "GuardDuty.svg",
    "iam": "Identity-and-Access-Management.svg",
    "inspector2": "Inspector.svg",
    "kms": "Key-Management-Service.svg",
    "lambda": "Lambda.svg",
    "lambda_logs": "Lambda.svg",
    "log_posture": "CloudTrail.svg",
    "macie": "Macie.svg",
    "network_firewall": "Network-Firewall.svg",
    "opensearch": "OpenSearch-Service.svg",
    "rds": "RDS.svg",
    "route53_resolver": "Route-53.svg",
    "s3": "Simple-Storage-Service.svg",
    "s3_access": "Simple-Storage-Service.svg",
    "secrets": "Secrets-Manager.svg",
    "securityhub": "Security-Hub.svg",
    "vpc_flow": "Virtual-Private-Cloud.svg",
    "waf": "WAF.svg",
}

AZURE = {
    "activity_log": ("00007-icon-service-Activity-Log.svg", "monitor"),
    "aks_audit": ("10023-icon-service-Kubernetes-Services.svg", "containers"),
    "app_gateway": ("10076-icon-service-Application-Gateways.svg", "networking"),
    "azure_firewall": ("10084-icon-service-Firewalls.svg", "networking"),
    "defender": ("10241-icon-service-Microsoft-Defender-for-Cloud.svg", "security"),
    "diag_posture": ("00009-icon-service-Log-Analytics-Workspaces.svg", "monitor"),
    "dns": ("10064-icon-service-DNS-Zones.svg", "networking"),
    "entra_audit": ("10235-icon-service-Identity-Governance.svg", "identity"),
    "entra_directory": ("10230-icon-service-Users.svg", "identity"),
    "entra_signin": ("03341-icon-service-Entra-Identity-Risky-Signins.svg", "security"),
    "front_door": ("10073-icon-service-Front-Door-and-CDN-Profiles.svg", "networking"),
    "key_vault": ("10245-icon-service-Key-Vaults.svg", "security"),
    "log_analytics": ("00009-icon-service-Log-Analytics-Workspaces.svg", "analytics"),
    "nsg_flow": ("10067-icon-service-Network-Security-Groups.svg", "networking"),
    "oauth_consent": ("10232-icon-service-App-Registrations.svg", "identity"),
    "rbac": ("10340-icon-service-Entra-Identity-Roles-and-Administrators.svg", "identity"),
    "resource_graph": ("10318-icon-service-Resource-Graph-Explorer.svg", None),
    "storage_access": ("10086-icon-service-Storage-Accounts.svg", "storage"),
    "subscription": ("10002-icon-service-Subscriptions.svg", "general"),
    "unified_audit": ("02931-icon-service-Compliance-Center.svg", None),
    "unified_audit_search": ("02931-icon-service-Compliance-Center.svg", None),
    "vnet_flow": ("10061-icon-service-Virtual-Networks.svg", "networking"),
}

GCP = {
    "api_gateway": "Cloud-API-Gateway.svg",
    "bigquery_audit": "BigQuery.svg",
    "cloud_armor": "Cloud-Armor.svg",
    "cloud_audit_admin": "Cloud-Audit-Logs.svg",
    "cloud_audit_data": "Cloud-Audit-Logs.svg",
    "cloud_audit_system": "Cloud-Audit-Logs.svg",
    "cloud_cdn": "Cloud-CDN.svg",
    "cloud_dns": "Cloud-DNS.svg",
    "cloud_functions": "Cloud-Functions.svg",
    "cloud_monitoring": "Cloud-Monitoring.svg",
    "cloud_nat": "Cloud-NAT.svg",
    "cloud_sql": "Cloud-SQL.svg",
    "firewall_logs": "Cloud-Firewall-Rules.svg",
    "gce": "Compute-Engine.svg",
    "gke_audit": "Google-Kubernetes-Engine.svg",
    "iam_policy": "Identity-And-Access-Management.svg",
    "load_balancer": "Cloud-Load-Balancing.svg",
    "logging_posture": "Cloud-Logging.svg",
    "login_events": "Identity-Platform.svg",
    "network_posture": "Cloud-Network.svg",
    "project": "Project.svg",
    "scc_findings": "Security-Command-Center.svg",
    "secret_manager": "Secret-Manager.svg",
    "storage_access": "Cloud-Storage.svg",
    "vm_logs": "Compute-Engine.svg",
    "vpc_flow": "Virtual-Private-Cloud.svg",
}

M365 = {
    "unified_audit": AZURE["unified_audit"],
    "unified_audit_search": AZURE["unified_audit_search"],
    "oauth_consent": AZURE["oauth_consent"],
}

# Official community icons (prefer unlabeled). Values are source filenames under K8S_ROOT/svg.
KUBERNETES = {
    "k8s_apiserver_audit": "api.svg",
    "k8s_audit_posture": "control-plane.svg",
    "k8s_events": "ns.svg",
    "k8s_cluster_state": "deploy.svg",
    "k8s_rbac": "c-role.svg",
    "k8s_container_logs": "pod.svg",
    "k8s_kubelet_logs": "kubelet.svg",
    "k8s_runtime_logs": "node.svg",
    "k8s_etcd": "etcd.svg",
    "k8s_cni_logs": "netpol.svg",
}

_TEXT_RE = re.compile(r"<text\b[^>]*>[\s\S]*?</text>", re.IGNORECASE)


def find_named(root: Path, filename: str, prefer: str | None = None) -> Path:
    matches = [p for p in root.rglob(filename) if p.is_file()]
    if prefer:
        preferred = [p for p in matches if prefer in p.as_posix()]
        if preferred:
            return preferred[0]
    if not matches:
        raise FileNotFoundError(filename)
    return matches[0]


def find_k8s_icon(filename: str) -> Path:
    """Prefer unlabeled community icons; fall back to labeled when unlabeled is missing."""
    matches = [p for p in (K8S_ROOT / "svg").rglob(filename) if p.is_file()]
    if not matches:
        raise FileNotFoundError(filename)
    unlabeled = [p for p in matches if "/unlabeled/" in p.as_posix()]
    if unlabeled:
        return unlabeled[0]
    return matches[0]


def copy_icon(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def copy_k8s_icon(src: Path, dest: Path) -> None:
    """Copy a K8s community SVG, stripping any embedded label text."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_text(encoding="utf-8")
    data = _TEXT_RE.sub("", data)
    dest.write_text(data, encoding="utf-8")


def main() -> int:
    if OUT.is_dir():
        shutil.rmtree(OUT)

    missing: list[str] = []

    for collector, filename in AWS.items():
        try:
            src = find_named(AWS_ROOT, filename)
            copy_icon(src, OUT / "aws" / f"{collector}.svg")
        except Exception as exc:
            missing.append(f"aws/{collector}: {exc}")

    for collector, (filename, prefer) in AZURE.items():
        try:
            src = find_named(AZURE_ROOT, filename, prefer)
            copy_icon(src, OUT / "azure" / f"{collector}.svg")
        except Exception as exc:
            missing.append(f"azure/{collector}: {exc}")

    for collector, filename in GCP.items():
        try:
            src = find_named(GCP_ROOT, filename)
            copy_icon(src, OUT / "gcp" / f"{collector}.svg")
        except Exception as exc:
            missing.append(f"gcp/{collector}: {exc}")

    for collector, (filename, prefer) in M365.items():
        try:
            src = find_named(AZURE_ROOT, filename, prefer)
            copy_icon(src, OUT / "m365" / f"{collector}.svg")
        except Exception as exc:
            missing.append(f"m365/{collector}: {exc}")

    for collector, filename in KUBERNETES.items():
        try:
            src = find_k8s_icon(filename)
            copy_k8s_icon(src, OUT / "kubernetes" / f"{collector}.svg")
        except Exception as exc:
            missing.append(f"kubernetes/{collector}: {exc}")

    # Provider badge logo (official wheel).
    logo_src = K8S_ROOT / "Kubernetes logo.svg"
    if logo_src.is_file():
        LOGOS_OUT.mkdir(parents=True, exist_ok=True)
        shutil.copy2(logo_src, LOGOS_OUT / "kubernetes.svg")

    wrote = list(OUT.rglob("*.svg"))
    print(f"Wrote {len(wrote)} SVGs to {OUT}")
    if missing:
        for line in missing:
            print("MISSING", line)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
