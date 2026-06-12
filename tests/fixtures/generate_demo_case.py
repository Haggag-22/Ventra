"""Generate a realistic synthetic Ventra evidence package for demos and tests.

The data tells one coherent story so the console has something meaningful to render:

    A leaked access key for IAM user `dbadmin` is used from a foreign IP. The attacker logs
    into the console, enumerates the account, escalates privilege by attaching
    AdministratorAccess, establishes persistence (new user + access key), disables CloudTrail
    logging, shares an EBS snapshot cross-account, reads objects from a sensitive S3 bucket,
    and exfiltrates data over the network. GuardDuty fires along the way.

No real data, no AWS calls. Produces a sealed .tar.zst|.tar.gz package via the collector's own
packaging code, so the demo exercises the real EPF path.

Usage:
    python tests/fixtures/generate_demo_case.py --out tests/fixtures/
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

# Make the collector importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "collector"))

from collector.lib.chain_of_custody.signing import sign_manifest  # noqa: E402
from collector.lib.models import (  # noqa: E402
    Manifest,
    Operator,
    SourceResult,
    SourceStatus,
    TimeWindow,
    WrittenFile,
    GapReason,
)
from collector.lib.packaging.packager import seal_package  # noqa: E402

ACCOUNT = "123456789012"
ALIAS = "client-prod"
REGION = "us-east-1"
ATTACKER_IP = "203.0.113.66"
ATTACKER_IP2 = "198.51.100.23"
LEGIT_IP = "52.94.236.10"
EXFIL_IP = "185.220.101.45"  # public, attacker-controlled
VICTIM_USER = "dbadmin"
VICTIM_ARN = f"arn:aws:iam::{ACCOUNT}:user/{VICTIM_USER}"
BASE = datetime(2026, 6, 7, 2, 14, 0, tzinfo=timezone.utc)

rng = random.Random(1337)


def _t(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ct(detail: dict) -> dict:
    """Wrap an inner CloudTrail detail the way LookupEvents returns it."""
    detail.setdefault("eventVersion", "1.09")
    detail.setdefault("awsRegion", REGION)
    detail.setdefault("recipientAccountId", ACCOUNT)
    return {"CloudTrailEvent": json.dumps(detail), "_ventra_region": REGION}


def _identity_user(name: str, ip: str, ua: str) -> dict:
    return {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLE0001",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "userName": name,
    }


def build_cloudtrail() -> list[dict]:
    events: list[dict] = []
    cli_ua = "aws-cli/2.15.0 Python/3.11"
    console_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    boto_ua = "Boto3/1.34 Python/3.11 Linux/5.10"

    # --- Normal baseline activity from the legitimate user (days before) ---
    for i in range(40):
        events.append(_ct({
            "eventTime": (BASE - timedelta(days=2) + timedelta(minutes=i * 7)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "eventName": rng.choice(["DescribeInstances", "ListBuckets", "GetCallerIdentity",
                                     "DescribeVolumes", "ListUsers"]),
            "eventSource": rng.choice(["ec2.amazonaws.com", "s3.amazonaws.com",
                                       "sts.amazonaws.com", "iam.amazonaws.com"]),
            "userIdentity": _identity_user(VICTIM_USER, LEGIT_IP, cli_ua),
            "sourceIPAddress": LEGIT_IP,
            "userAgent": cli_ua,
        }))

    # --- 02:14 Console login from foreign IP (attacker) ---
    events.append(_ct({
        "eventTime": _t(0),
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP, console_ua),
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": console_ua,
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }))

    # --- 02:15-02:25 Reconnaissance burst ---
    recon = ["GetCallerIdentity", "ListUsers", "ListRoles", "ListAccessKeys",
             "GetAccountAuthorizationDetails", "ListBuckets", "DescribeInstances",
             "ListAttachedUserPolicies", "GetAccountSummary", "ListGroupsForUser",
             "DescribeSnapshots", "DescribeSecurityGroups"]
    for i, name in enumerate(recon):
        denied = name in ("GetAccountAuthorizationDetails",)  # one AccessDenied
        events.append(_ct({
            "eventTime": _t(60 + i * 45),
            "eventName": name,
            "eventSource": ("iam.amazonaws.com" if name.startswith(("List", "Get")) and
                            "Bucket" not in name else "ec2.amazonaws.com"),
            "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP, boto_ua),
            "sourceIPAddress": ATTACKER_IP,
            "userAgent": boto_ua,
            **({"errorCode": "AccessDenied", "errorMessage": "not authorized"} if denied else {}),
        }))

    # --- 02:27 Privilege escalation: attach AdministratorAccess ---
    events.append(_ct({
        "eventTime": _t(780),
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP, boto_ua),
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": boto_ua,
        "requestParameters": {"userName": VICTIM_USER,
                              "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    }))

    # --- 02:29 Persistence: create user + access key ---
    events.append(_ct({
        "eventTime": _t(900),
        "eventName": "CreateUser",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP, boto_ua),
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": boto_ua,
        "requestParameters": {"userName": "support-helper"},
    }))
    events.append(_ct({
        "eventTime": _t(940),
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP, boto_ua),
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": boto_ua,
        "requestParameters": {"userName": "support-helper"},
    }))

    # --- 02:33 Defense evasion: stop CloudTrail logging ---
    events.append(_ct({
        "eventTime": _t(1140),
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP, boto_ua),
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": boto_ua,
        "requestParameters": {"name": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail"},
    }))

    # --- 02:36 Data: share an EBS snapshot cross-account ---
    events.append(_ct({
        "eventTime": _t(1320),
        "eventName": "ModifySnapshotAttribute",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP2, boto_ua),
        "sourceIPAddress": ATTACKER_IP2,
        "userAgent": boto_ua,
        "requestParameters": {
            "snapshotId": "snap-0ab12cd34ef56",
            "createVolumePermission": {"add": {"items": [{"userId": "999988887777"}]}},
        },
    }))

    # --- 02:38-02:50 Data access: GetObject on sensitive bucket ---
    for i in range(15):
        events.append(_ct({
            "eventTime": _t(1380 + i * 40),
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "userIdentity": _identity_user(VICTIM_USER, ATTACKER_IP2, boto_ua),
            "sourceIPAddress": ATTACKER_IP2,
            "userAgent": boto_ua,
            "requestParameters": {"bucketName": "client-prod-db-backups",
                                  "key": f"exports/customers-{i}.sql.gz"},
            "resources": [{"type": "AWS::S3::Object",
                           "ARN": f"arn:aws:s3:::client-prod-db-backups/exports/customers-{i}.sql.gz"}],
        }))

    return events


def build_sts() -> list[dict]:
    """AssumeRole events for the Identity panel's role-assumption graph."""
    boto_ua = "Boto3/1.34 Python/3.11 Linux/5.10"
    def assume(actor_arn, actor_name, role_arn, ip, when, utype="IAMUser"):
        return _ct({
            "eventTime": when, "eventName": "AssumeRole", "eventSource": "sts.amazonaws.com",
            "userIdentity": {"type": utype, "arn": actor_arn, "userName": actor_name,
                             "accountId": ACCOUNT, "principalId": "AIDAEXAMPLE"},
            "sourceIPAddress": ip, "userAgent": boto_ua,
            "requestParameters": {"roleArn": role_arn, "roleSessionName": "sess"},
            "responseElements": {"assumedRoleUser": {
                "arn": role_arn.replace(":role/", ":assumed-role/") + "/sess"}},
        })
    app_role = f"arn:aws:iam::{ACCOUNT}:role/app-role"
    org_role = f"arn:aws:iam::{ACCOUNT}:role/OrganizationAccountAccessRole"
    events = []
    # Legit CI assuming the app role repeatedly (baseline).
    for i in range(12):
        events.append(assume(f"arn:aws:iam::{ACCOUNT}:user/ci-deploy", "ci-deploy", app_role,
                             LEGIT_IP, (BASE - timedelta(days=1) + timedelta(hours=i)).strftime(
                                 "%Y-%m-%dT%H:%M:%SZ")))
    # Attacker pivoting to the powerful org role.
    events.append(assume(VICTIM_ARN, VICTIM_USER, org_role, ATTACKER_IP2, _t(1260)))
    events.append(assume(VICTIM_ARN, VICTIM_USER, app_role, ATTACKER_IP2, _t(1280)))
    return events


def build_guardduty() -> list[dict]:
    def finding(ftype, sev, title, ip, when, user=VICTIM_USER):
        return {
            "AccountId": ACCOUNT, "Region": REGION, "Type": ftype, "Severity": sev,
            "Title": title, "CreatedAt": when, "UpdatedAt": when,
            "Service": {"Action": {"AwsApiCallAction": {"RemoteIpDetails": {
                "IpAddressV4": ip, "Country": {"CountryName": "Russia"},
                "Organization": {"Asn": 49505}}}}},
            "Resource": {"ResourceType": "AccessKey",
                         "AccessKeyDetails": {"UserName": user, "UserType": "IAMUser"}},
        }
    return [
        finding("UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", 7.5,
                "Console login from a Tor exit node", ATTACKER_IP, _t(30)),
        finding("Recon:IAMUser/MaliciousIPCaller", 5.0,
                "API calls from a known malicious IP", ATTACKER_IP, _t(300)),
        finding("PrivilegeEscalation:IAMUser/AdministrativePermissions", 8.0,
                "Administrative policy attached to user", ATTACKER_IP, _t(800)),
        finding("Persistence:IAMUser/AnomalousBehavior", 7.0,
                "Anomalous IAM user creation", ATTACKER_IP, _t(960)),
        finding("Stealth:IAMUser/CloudTrailLoggingDisabled", 8.5,
                "CloudTrail logging was disabled", ATTACKER_IP, _t(1160)),
        finding("Exfiltration:S3/AnomalousBehavior", 8.0,
                "Anomalous S3 data retrieval volume", ATTACKER_IP2, _t(1500)),
    ]


def build_vpc_flow() -> list[dict]:
    """CloudWatch-style flow records (message holds the v2 line)."""
    eni = "eni-0a1b2c3d4e5f6"
    out = []
    start = int((BASE + timedelta(seconds=1400)).timestamp())
    # Normal internal chatter.
    for i in range(30):
        s = start + i * 5
        out.append({"_ventra_region": REGION, "timestamp": s * 1000,
                    "message": f"2 {ACCOUNT} {eni} 10.0.1.20 10.0.2.30 51514 443 6 12 1500 "
                               f"{s} {s+10} ACCEPT OK"})
    # Large exfil egress to a public IP.
    for i in range(12):
        s = start + 200 + i * 7
        nbytes = rng.randint(40_000_000, 90_000_000)
        out.append({"_ventra_region": REGION, "timestamp": s * 1000,
                    "message": f"2 {ACCOUNT} {eni} 10.0.1.20 {EXFIL_IP} 49888 443 6 8000 {nbytes} "
                               f"{s} {s+30} ACCEPT OK"})
    # Rejected recon scans inbound.
    for i in range(20):
        s = start + 50 + i * 3
        port = rng.choice([22, 3389, 445, 23])
        out.append({"_ventra_region": REGION, "timestamp": s * 1000,
                    "message": f"2 {ACCOUNT} {eni} {ATTACKER_IP} 10.0.1.20 40000 {port} 6 3 120 "
                               f"{s} {s+5} REJECT OK"})
    return out


def build_iam_snapshot() -> dict:
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    readonly_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    s3_read_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    return {
        "users": [
            {"UserName": VICTIM_USER, "Arn": VICTIM_ARN, "CreateDate": "2024-03-01T10:00:00Z",
             "AttachedManagedPolicies": [
                 {"PolicyName": "AdministratorAccess", "PolicyArn": admin_arn}],
             "UserPolicyList": [],
             "GroupList": [],
             "AccessKeys": [
                 {"AccessKeyId": "AKIAEXAMPLEOLD01", "Status": "Active",
                  "CreateDate": "2024-03-01T10:00:00Z",
                  "LastUsed": {"LastUsedDate": _t(60), "ServiceName": "iam", "Region": REGION}}],
             "MFADevices": []},
            {"UserName": "support-helper",
             "Arn": f"arn:aws:iam::{ACCOUNT}:user/support-helper",
             "CreateDate": _t(900),
             "AttachedManagedPolicies": [],
             "UserPolicyList": [{
                 "PolicyName": "persist-access",
                 "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                     "Effect": "Allow", "Action": ["iam:*", "sts:AssumeRole"], "Resource": "*"}]},
             }],
             "GroupList": [],
             "AccessKeys": [
                 {"AccessKeyId": "AKIAEXAMPLENEW99", "Status": "Active",
                  "CreateDate": _t(940), "LastUsed": {}}],
             "MFADevices": []},
            {"UserName": "ci-deploy", "Arn": f"arn:aws:iam::{ACCOUNT}:user/ci-deploy",
             "CreateDate": "2023-01-15T08:00:00Z",
             "AttachedManagedPolicies": [
                 {"PolicyName": "ReadOnlyAccess", "PolicyArn": readonly_arn}],
             "UserPolicyList": [],
             "GroupList": ["deployers"],
             "AccessKeys": [
                 {"AccessKeyId": "AKIAEXAMPLECI001", "Status": "Active",
                  "CreateDate": "2023-01-15T08:00:00Z", "LastUsed": {}}],
             "MFADevices": []},
        ],
        "roles": [
            {"RoleName": "app-role", "Arn": f"arn:aws:iam::{ACCOUNT}:role/app-role",
             "CreateDate": "2023-06-01T00:00:00Z",
             "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                 "Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                 "Action": "sts:AssumeRole"}]},
             "AttachedManagedPolicies": [
                 {"PolicyName": "AmazonS3ReadOnlyAccess", "PolicyArn": s3_read_arn}],
             "RolePolicyList": []},
            {"RoleName": "OrganizationAccountAccessRole",
             "Arn": f"arn:aws:iam::{ACCOUNT}:role/OrganizationAccountAccessRole",
             "CreateDate": "2022-01-01T00:00:00Z",
             "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                 "Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                 "Action": "sts:AssumeRole"}]},
             "AttachedManagedPolicies": [
                 {"PolicyName": "AdministratorAccess", "PolicyArn": admin_arn}],
             "RolePolicyList": []},
        ],
        "groups": [{
            "GroupName": "deployers",
            "Arn": f"arn:aws:iam::{ACCOUNT}:group/deployers",
            "CreateDate": "2023-01-01T00:00:00Z",
            "AttachedManagedPolicies": [
                {"PolicyName": "ReadOnlyAccess", "PolicyArn": readonly_arn}],
            "GroupPolicyList": [],
        }],
        "policies": [],
        "password_policy": {"MinimumPasswordLength": 8, "RequireSymbols": False},
    }


def build_s3_inventory() -> dict:
    return {"buckets": [
        {"name": "client-prod-db-backups", "region": REGION, "creation_date": "2023-02-01",
         "logging": None, "_ventra_no_access_logging": True,
         "policy_status": {"IsPublic": False}, "object_lock": None},
        {"name": "client-prod-assets", "region": REGION, "creation_date": "2023-02-01",
         "logging": {"TargetBucket": "client-prod-logs"},
         "policy_status": {"IsPublic": True}, "_ventra_public": True},
        {"name": "client-prod-logs", "region": REGION, "creation_date": "2023-02-01",
         "logging": None, "policy_status": {"IsPublic": False}},
    ]}


def build_ec2_inventory() -> dict:
    return {
        "instances": [
            {"InstanceId": "i-0web001", "_ventra_region": REGION, "State": {"Name": "running"},
             "PrivateIpAddress": "10.0.1.20", "PublicIpAddress": "52.0.0.20",
             "InstanceType": "t3.large", "ImageId": "ami-0abc"},
            {"InstanceId": "i-0db002", "_ventra_region": REGION, "State": {"Name": "running"},
             "PrivateIpAddress": "10.0.2.30", "InstanceType": "r5.xlarge", "ImageId": "ami-0def"},
        ],
        "volumes": [{"VolumeId": "vol-0db", "_ventra_region": REGION, "Size": 500}],
        "snapshots": [
            {"SnapshotId": "snap-0ab12cd34ef56", "_ventra_region": REGION, "VolumeSize": 500,
             "Encrypted": False, "StartTime": _t(1300),
             "Description": "db nightly", "Shared": True, "OwnerAlias": ""}],
        "network_interfaces": [], "security_groups": [
            {"GroupId": "sg-0web", "GroupName": "web-sg", "_ventra_region": REGION,
             "IpPermissions": [{"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp",
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
        "launch_templates": [],
    }


def build_account_snapshot() -> dict:
    return {"account_id": ACCOUNT, "account_alias": ALIAS,
            "operator_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/IR-Responder/omar",
            "operator_user_id": "AROAEXAMPLE:omar", "partition": "aws",
            "regions_in_scope": [REGION], "org_id": "o-exampleorg123"}


def _write_gz_jsonl(path: Path, records: list[dict]) -> WrittenFile:
    # Hash the stored (compressed) bytes — that is what the ingester re-hashes on import.
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


def generate(out_dir: Path, case_id: str = "CASE-2026-0042") -> Path:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ventra-demo-") as tmp:
        staging = Path(tmp)
        manifest = Manifest(
            schema_version="1.0.0", tool_version="0.1.0", case_id=case_id,
            cloud="aws", account_id=ACCOUNT, account_alias=ALIAS, partition="aws",
            org_id="o-exampleorg123", regions=[REGION],
            operator=Operator(principal_arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/IR-Responder/omar",
                              user_id="AROAEXAMPLE:omar", source_ip="100.64.0.10"),
            started_at=_t(-10), completed_at=_t(2000),
            profile_name="all",
            host_environment="cloudshell", host_os="Amazon Linux 2023",
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
        # Event sources
        src("cloudtrail", [("events.jsonl.gz", _write_gz_jsonl(sd / "cloudtrail/events.jsonl.gz",
                                                               build_cloudtrail())),
                           ("config.json", _write_json(sd / "cloudtrail/config.json",
                               {"trails": [{
                                    "Name": "org-trail",
                                    "TrailARN": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail",
                                    "HomeRegion": REGION,
                                    "S3BucketName": "company-cloudtrail-logs",
                                    "S3KeyPrefix": "org/",
                                    "IsMultiRegionTrail": True,
                                    "LogFileValidationEnabled": True,
                                    "Status": {"IsLogging": True},
                                }],
                                "trail_count": 1,
                                "any_log_validation_enabled": True,
                                "event_coverage": {
                                    "data_events_configured": True,
                                    "network_activity_configured": False,
                                    "insight_events_configured": True,
                                    "s3_logging_trails": 1,
                                },
                                "collection_summary": {
                                    "trail_count": 1,
                                    "trails": [{
                                        "name": "org-trail",
                                        "arn": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail",
                                        "home_region": REGION,
                                        "s3_bucket": "company-cloudtrail-logs",
                                        "s3_key_prefix": "org/",
                                        "is_logging": True,
                                        "is_multi_region": True,
                                        "is_organization": False,
                                        "log_file_validation": True,
                                        "data_events_configured": True,
                                        "insight_events_configured": True,
                                        "network_activity_configured": False,
                                    }],
                                    "events": {
                                        "lookup_api": {"management": 42, "insight": 0, "total": 42},
                                        "s3": {
                                            "total": 0,
                                            "data": 0,
                                            "insight": 0,
                                            "network_activity": 0,
                                            "by_bucket": [],
                                        },
                                    },
                                }})),
                           ("_meta.json", _write_json(sd / "cloudtrail/_meta.json", {
                                "source": "cloudtrail",
                                "records": 42,
                                "management_events": 42,
                                "trails": 1,
                            }))],
            notes="Management events + trail config.")
        src("sts", [("events.jsonl.gz", _write_gz_jsonl(sd / "sts/events.jsonl.gz",
                                                        build_sts()))],
            notes="AssumeRole activity.")
        src("guardduty", [("events.jsonl.gz", _write_gz_jsonl(sd / "guardduty/events.jsonl.gz",
                                                              build_guardduty()))],
            notes="6 findings.")
        src("vpc_flow", [("events.jsonl.gz", _write_gz_jsonl(sd / "vpc_flow/events.jsonl.gz",
                                                            build_vpc_flow())),
                         ("config.json", _write_json(sd / "vpc_flow/config.json",
                             {"flow_logs": [{"LogDestinationType": "cloud-watch-logs",
                                             "LogGroupName": "/vpc/flowlogs"}]}))],
            notes="Flow records incl. exfil egress.")
        # Inventory sources
        src("iam", [("snapshot.json", _write_json(sd / "iam/snapshot.json", build_iam_snapshot()))],
            notes="3 users, 2 roles.")
        src("s3", [("snapshot.json", _write_json(sd / "s3/snapshot.json", build_s3_inventory()))],
            notes="3 buckets, 1 public.")
        src("ec2", [("snapshot.json", _write_json(sd / "ec2/snapshot.json", build_ec2_inventory()))],
            notes="2 instances; 1 shared snapshot.")
        src("account", [("snapshot.json", _write_json(sd / "account/snapshot.json",
                                                       build_account_snapshot()))],
            notes="Environment context.")
        # A deliberate gap: WAF not configured.
        manifest.add_source_result(SourceResult(
            name="waf", status=SourceStatus.EMPTY,
            gaps=[("waf", GapReason.NOT_PRESENT, "No WAFv2 Web ACLs in scope.")],
            notes="No WAF configured."))

        # collection log + manifest + sign + seal
        (staging / "collection.log").write_text(
            "\n".join(json.dumps({"collector": s["name"], "status": s["status"]})
                      for s in manifest.sources) + "\n", encoding="utf-8")
        manifest_path = staging / "manifest.json"
        manifest.write(manifest_path)
        sign_manifest(manifest_path, None)
        result = seal_package(staging, out_dir, case_id, ACCOUNT)
        return result.path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a synthetic Ventra demo package.")
    ap.add_argument("--out", default="tests/fixtures", help="Output directory.")
    ap.add_argument("--case", default="CASE-2026-0042")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = generate(out, args.case)
    print(f"Wrote demo package: {path}")
    print(f"  size: {path.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
