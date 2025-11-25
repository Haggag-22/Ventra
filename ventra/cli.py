#!/usr/bin/env python3

import argparse
import boto3
from botocore.exceptions import ClientError

from ventra.auth.whoami import aws_whoami
from ventra.auth.store import save_ventra_profile
from ventra.collector.cloudtrail.cloudtrail_history import run_cloudtrail_history
from ventra.collector.cloudtrail.cloudtrail_s3 import run_cloudtrail_s3
from ventra.case.store import create_case, list_cases, get_or_create_case


# =============================================================================
# REGION RESOLUTION
# =============================================================================
def resolve_region(args):
    """
    Priority:
      1. CLI flag --region
      2. Ventra profile stored region
      3. fallback: us-east-1
    """

    if getattr(args, "region", None):
        return args.region

    try:
        from ventra.auth.store import load_ventra_creds
        creds = load_ventra_creds(args.profile)
        return creds.get("region", "us-east-1")
    except Exception:
        return "us-east-1"


# =============================================================================
# ROUTING
# =============================================================================
def route(args):

    # -------------------------------------------------------------------------
    # AUTH
    # -------------------------------------------------------------------------
    if args.command == "auth":
        # Validate credentials
        try:
            session = boto3.Session(
                aws_access_key_id=args.access_key,
                aws_secret_access_key=args.secret_key,
                region_name=args.region,
            )
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            print(f"[✓] Valid credentials for ARN: {identity['Arn']}")
        except ClientError as e:
            print(f"❌ Invalid AWS credentials: {e}")
            return

        save_ventra_profile(
            profile=args.profile,
            access_key=args.access_key,
            secret_key=args.secret_key,
            region=args.region,
        )
        return

    # -------------------------------------------------------------------------
    # WHOAMI
    # -------------------------------------------------------------------------
    if args.command == "whoami":
        info = aws_whoami(args.profile)

        if "error" in info:
            print(f"\n❌ Error: {info['error']}\n")
            return

        print("\n" + "=" * 60)
        print("  AWS Identity (Ventra Profile)")
        print("=" * 60)
        print(f"  Profile  : {info.get('Profile', 'N/A')}")
        print(f"  Account  : {info.get('Account', 'N/A')}")
        print(f"  Region   : {info.get('Region', 'N/A')}")
        print(f"  User ID  : {info.get('UserId', 'N/A')}")
        print(f"  ARN      : {info.get('Arn', 'N/A')}")
        print("=" * 60 + "\n")
        return

    # -------------------------------------------------------------------------
    # CASE
    # -------------------------------------------------------------------------
    if args.command == "case":
        if args.case_cmd == "new":
            case_name, case_dir = create_case(args.name)
            print(f"[✓] Created case: {case_name} ({args.name})")
            return
        
        if args.case_cmd == "list":
            cases = list_cases()
            if not cases:
                print("[!] No cases found.")
                return
            
            print("\n" + "=" * 60)
            print("  Cases")
            print("=" * 60)
            for case in cases:
                print(f"  {case['name']}")
            print("=" * 60 + "\n")
            return

    # -------------------------------------------------------------------------
    # COLLECT
    # -------------------------------------------------------------------------
    if args.command == "collect":

        # override region on args for collectors
        args.region = resolve_region(args)

        # Resolve case (required, will create if doesn't exist)
        case_identifier = args.case
        case_name, case_dir = get_or_create_case(case_identifier)
        args.case_dir = case_dir
        args.case_name = case_name

        if args.collect_target == "cloudtrail":

            if args.cloudtrail_cmd == "history":
                return run_cloudtrail_history(args)

            if args.cloudtrail_cmd == "s3":
                return run_cloudtrail_s3(args)

            if args.cloudtrail_cmd == "all":
                print("[+] Running CloudTrail history + s3 collectors...")
                run_cloudtrail_history(args)
                run_cloudtrail_s3(args)
                print("[✓] Completed combined collectors.")
                return


# =============================================================================
# CLI BUILDER
# =============================================================================
def build_cli():

    parser = argparse.ArgumentParser(
        prog="ventra",
        description="Ventra DFIR Collection & Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # =========================================================================
    # WHOAMI
    # =========================================================================
    whoami = sub.add_parser("whoami", help="Show active AWS identity/profile")
    whoami.add_argument("--profile", type=str, help="Ventra internal profile")
    whoami.add_argument("--region", type=str)

    # =========================================================================
    # AUTH
    # =========================================================================
    auth = sub.add_parser("auth", help="Configure Ventra internal AWS profile")
    auth.add_argument("--profile", type=str, required=True, help="Profile name")
    auth.add_argument("--access-key", type=str, required=True, help="AWS access key ID")
    auth.add_argument("--secret-key", type=str, required=True, help="AWS secret access key")
    auth.add_argument("--region", type=str, required=True, help="AWS region")

    # =========================================================================
    # CASE
    # =========================================================================
    case = sub.add_parser("case", help="Manage cases")
    case_sub = case.add_subparsers(dest="case_cmd", required=True)
    
    case_new = case_sub.add_parser("new", help="Create a new case")
    case_new.add_argument("--name", type=str, required=True, help="Case name")
    
    case_list = case_sub.add_parser("list", help="List all cases")

    # =========================================================================
    # COLLECT
    # =========================================================================
    collect = sub.add_parser("collect", help="Run Ventra collectors")
    collect.add_argument("--profile", type=str, help="Ventra internal profile")
    collect.add_argument("--region", type=str, help="Override region")

    collect_sub = collect.add_subparsers(dest="collect_target", required=True)

    # CLOUDTRAIL
    ct = collect_sub.add_parser("cloudtrail")
    ct_sub = ct.add_subparsers(dest="cloudtrail_cmd", required=True)

    # history
    ct_hist = ct_sub.add_parser("history")
    ct_hist.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ct_hist.add_argument("--hours", type=int, required=True)
    ct_hist.add_argument("--output", type=str)

    # s3
    ct_s3 = ct_sub.add_parser("s3")
    ct_s3.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ct_s3.add_argument("--bucket", type=str, required=True, help="S3 bucket name containing CloudTrail logs")
    ct_s3.add_argument("--prefix", type=str, help="S3 prefix path (e.g., 'AWSLogs/525426937582/CloudTrail/us-east-1/2025/11/23'). Optional - auto-discovers all logs if not provided.")
    ct_s3.add_argument("--output", type=str)

    # all
    ct_all = ct_sub.add_parser("all")
    ct_all.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ct_all.add_argument("--hours", type=int, required=True)
    ct_all.add_argument("--bucket", type=str, required=True)
    ct_all.add_argument("--prefix", type=str, required=True)
    ct_all.add_argument("--output", type=str)

    return parser


# =============================================================================
# MAIN
# =============================================================================
def main():
    parser = build_cli()
    args = parser.parse_args()
    route(args)


if __name__ == "__main__":
    main()