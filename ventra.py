#!/usr/bin/env python3
import argparse
import os
import json
from pathlib import Path

# Collectors
from collector.cloudtrail.cloudtrail_history import run_cloudtrail_history
from collector.cloudtrail.cloudtrail_s3 import run_cloudtrail_s3


# =============================================================================
# CONFIG STORE
# =============================================================================
CONFIG_PATH = os.path.expanduser("~/.ventra/config.json")


def save_auth(profile=None, access_key=None, secret_key=None, region="us-east-1"):
    Path(os.path.dirname(CONFIG_PATH)).mkdir(parents=True, exist_ok=True)

    data = {
        "profile": profile,
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "region": region,
    }

    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[✓] Saved Ventra auth configuration → {CONFIG_PATH}")


# =============================================================================
# ROUTING
# =============================================================================
def route(args):

    # --- AUTH ---
    if args.command == "auth":
        save_auth(
            profile=args.profile,
            access_key=args.access_key,
            secret_key=args.secret_key,
            region=args.region,
        )
        return

    # --- COLLECT ---
    if args.command == "collect":

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
        
        elif args.collect_target == "ec2":
            pass

    if args.command == "analyze":
        pass
    
    if args.command == "timeline":
        pass
    


# =============================================================================
# CLI BUILDER
# =============================================================================
def build_cli():

    epilog = """
Examples:

  ventra auth --profile dfir-profile

  ventra collect cloudtrail history --hours 12

  ventra collect cloudtrail s3 --bucket mybucket --prefix AWSLogs/123456789012/

  ventra collect cloudtrail all --hours 24 --bucket bucket --prefix AWSLogs/12345/
"""

    parser = argparse.ArgumentParser(
        prog="ventra",
        description="Ventra DFIR Collection & Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # =========================================================================
    # AUTH
    # =========================================================================
    auth = sub.add_parser("auth", help="Configure AWS authentication for Ventra")
    auth.add_argument("--profile", type=str, help="AWS profile name")
    auth.add_argument("--access-key", type=str, help="AWS access key ID")
    auth.add_argument("--secret-key", type=str, help="AWS secret access key")
    auth.add_argument("--region", type=str, default="us-east-1")

    # =========================================================================
    # COLLECT
    # =========================================================================
    collect = sub.add_parser("collect", help="Run Ventra collectors")
    collect_sub = collect.add_subparsers(dest="collect_target", required=True)

    # =========================================================================
    # CLOUDTRAIL
    # =========================================================================
    ct = collect_sub.add_parser("cloudtrail", help="CloudTrail collectors")
    ct_sub = ct.add_subparsers(dest="cloudtrail_cmd", required=True)

    # ---------------- HISTORY ----------------
    ct_hist = ct_sub.add_parser("history", help="Collect CloudTrail LookupEvents history")

    req_hist = ct_hist.add_argument_group("required arguments")
    req_hist.add_argument("--hours", type=int, required=True, help="Hours back to collect")

    opt_hist = ct_hist.add_argument_group("optional arguments")
    opt_hist.add_argument("--output", type=str, help="Optional output directory")

    # ---------------- S3 ----------------
    ct_s3 = ct_sub.add_parser("s3", help="Collect CloudTrail S3 raw .json.gz logs")

    req_s3 = ct_s3.add_argument_group("required arguments")
    req_s3.add_argument("--bucket", type=str, required=True, help="CloudTrail S3 bucket")
    req_s3.add_argument("--prefix", type=str, required=True, help="S3 prefix under bucket")

    opt_s3 = ct_s3.add_argument_group("optional arguments")
    opt_s3.add_argument("--output", type=str, help="Optional output directory")

    # ---------------- ALL ----------------
    ct_all = ct_sub.add_parser("all", help="Run both history + s3 collectors")

    req_all = ct_all.add_argument_group("required arguments")
    req_all.add_argument("--hours", type=int, required=True)
    req_all.add_argument("--bucket", type=str, required=True)
    req_all.add_argument("--prefix", type=str, required=True)

    opt_all = ct_all.add_argument_group("optional arguments")
    opt_all.add_argument("--output", type=str)

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
