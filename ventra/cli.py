#!/usr/bin/env python3

import argparse
import boto3
from botocore.exceptions import ClientError

from ventra.auth.whoami import aws_whoami
from ventra.auth.store import save_ventra_profile
from ventra.collector.cloudtrail.cloudtrail_history import run_cloudtrail_history
from ventra.collector.cloudtrail.cloudtrail_s3 import run_cloudtrail_s3
from ventra.collector.cloudtrail.cloudtrail_lake import run_cloudtrail_lake
from ventra.collector.ec2.ec2_metadata_passive import run_ec2_meta_external
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
    # NORMALIZE
    # -------------------------------------------------------------------------
    if args.command == "normalize":
        from ventra.case.store import get_case_dir
        from ventra.normalization import run_from_args
        
        # Resolve case directory
        case_identifier = args.case
        case_dir = get_case_dir(case_identifier)
        
        if not case_dir:
            print(f"❌ Case not found: {case_identifier}")
            print("    Use 'ventra case list' to see available cases")
            return
        
        # Set case_dir on args for run_from_args
        args.case_dir = case_dir
        
        # Optionally resolve account_id and region from whoami if not provided
        if not args.account_id or not args.region:
            try:
                info = aws_whoami(args.profile)
                if "error" not in info:
                    if not args.account_id:
                        args.account_id = info.get("Account")
                    if not args.region:
                        args.region = info.get("Region")
            except Exception:
                pass  # Continue without account_id/region if whoami fails
        
        # Run normalization pipeline
        try:
            summaries = run_from_args(args)
            
            # Print summary
            print("\n" + "=" * 60)
            print("  Normalization Summary")
            print("=" * 60)
            for summary in summaries:
                status = "✓" if summary.error_count == 0 else "⚠"
                print(f"  {status} {summary.name}: {summary.record_count} records, {summary.error_count} errors")
                print(f"    → {summary.output_path}")
            print("=" * 60 + "\n")
        except Exception as e:
            print(f"❌ Normalization error: {e}")
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

            if args.cloudtrail_cmd == "lake":
                return run_cloudtrail_lake(args)

            if args.cloudtrail_cmd == "all":
                print("[+] Running CloudTrail history + s3 collectors...")
                run_cloudtrail_history(args)
                run_cloudtrail_s3(args)
                print("[✓] Completed combined collectors.")
                return

        if args.collect_target == "ec2":
            if args.ec2_cmd == "metadata-passive":
                # Parse comma-separated instance IDs
                if isinstance(args.instance, str):
                    args.instance = [i.strip() for i in args.instance.split(",") if i.strip()]
                return run_ec2_meta_external(args)
            
            if args.ec2_cmd == "metadata-active":
                # Parse comma-separated instance IDs
                if isinstance(args.instance, str):
                    args.instance = [i.strip() for i in args.instance.split(",") if i.strip()]
                from ventra.collector.ec2.ec2_metadata_active import run_ec2_metadata_active
                return run_ec2_metadata_active(args)
            
            if args.ec2_cmd == "volumes":
                from ventra.collector.ec2.ec2_volumes import run_ec2_volumes
                return run_ec2_volumes(args)
            
            if args.ec2_cmd == "snapshots":
                from ventra.collector.ec2.ec2_snapshots import run_ec2_snapshots
                return run_ec2_snapshots(args)
            
            if args.ec2_cmd == "all":
                from ventra.collector.ec2.ec2_all import run_ec2_all
                return run_ec2_all(args)
        
        if args.collect_target == "vpc":
            from ventra.collector.vpc.vpc import (
                collect_vpc_info,
                collect_vpc_subnets,
                collect_vpc_routes,
                collect_vpc_security_groups,
                collect_vpc_nacls,
                collect_vpc_endpoints,
                collect_vpc_internet_gateways,
                collect_vpc_nat_gateways,
                collect_vpc_flow_logs,
                collect_vpc_all,
            )
            
            if args.vpc_cmd == "info":
                return collect_vpc_info(args)
            if args.vpc_cmd == "subnets":
                return collect_vpc_subnets(args)
            if args.vpc_cmd == "routes":
                return collect_vpc_routes(args)
            if args.vpc_cmd == "sg":
                return collect_vpc_security_groups(args)
            if args.vpc_cmd == "nacl":
                return collect_vpc_nacls(args)
            if args.vpc_cmd == "endpoints":
                return collect_vpc_endpoints(args)
            if args.vpc_cmd == "igw":
                return collect_vpc_internet_gateways(args)
            if args.vpc_cmd == "nat":
                return collect_vpc_nat_gateways(args)
            if args.vpc_cmd == "flowlogs":
                return collect_vpc_flow_logs(args)
            if args.vpc_cmd == "all":
                return collect_vpc_all(args)
        
        if args.collect_target == "iam":
            from ventra.collector.iam.iam import run_iam_all
            from ventra.collector.iam.users import run_iam_user
            from ventra.collector.iam.roles import run_iam_role
            from ventra.collector.iam.groups import run_iam_group
            from ventra.collector.iam.policies import run_iam_policy
            
            if args.iam_cmd == "all":
                return run_iam_all(args)
            if args.iam_cmd == "user":
                return run_iam_user(args)
            if args.iam_cmd == "role":
                return run_iam_role(args)
            if args.iam_cmd == "group":
                return run_iam_group(args)
            if args.iam_cmd == "policy":
                return run_iam_policy(args)
        
        if args.collect_target == "s3":
            from ventra.collector.s3.s3_bucket_info import run_s3_bucket_info
            from ventra.collector.s3.s3_access import run_s3_access
            from ventra.collector.s3.s3_objects import run_s3_objects
            from ventra.collector.s3.s3_versions import run_s3_versions
            from ventra.collector.s3.s3_all import run_s3_all
            
            if args.s3_cmd == "bucket-info":
                return run_s3_bucket_info(args)
            if args.s3_cmd == "access":
                return run_s3_access(args)
            if args.s3_cmd == "objects":
                return run_s3_objects(args)
            if args.s3_cmd == "versions":
                return run_s3_versions(args)
            if args.s3_cmd == "all":
                return run_s3_all(args)
        
        if args.collect_target == "guradduty":
            from ventra.collector.guradduty.guradduty_detectors import run_guradduty_detectors
            from ventra.collector.guradduty.guradduty_findings import run_guradduty_findings
            from ventra.collector.guradduty.guradduty_details import run_guradduty_details
            from ventra.collector.guradduty.guradduty_malware import run_guradduty_malware
            from ventra.collector.guradduty.guradduty_all import run_guradduty_all
            
            if args.guradduty_cmd == "detectors":
                return run_guradduty_detectors(args)
            if args.guradduty_cmd == "findings":
                return run_guradduty_findings(args)
            if args.guradduty_cmd == "details":
                return run_guradduty_details(args)
            if args.guradduty_cmd == "malware":
                return run_guradduty_malware(args)
            if args.guradduty_cmd == "all":
                return run_guradduty_all(args)
        
        if args.collect_target == "cloudwatch":
            from ventra.collector.cloudwatch.cloudwatch_log_groups import run_cloudwatch_log_groups
            from ventra.collector.cloudwatch.cloudwatch_logs import run_cloudwatch_logs
            from ventra.collector.cloudwatch.cloudwatch_metrics import run_cloudwatch_metrics
            from ventra.collector.cloudwatch.cloudwatch_alarms import run_cloudwatch_alarms
            from ventra.collector.cloudwatch.cloudwatch_events import run_cloudwatch_events
            from ventra.collector.cloudwatch.cloudwatch_dashboards import run_cloudwatch_dashboards
            from ventra.collector.cloudwatch.cloudwatch_all import run_cloudwatch_all
            
            if args.cloudwatch_cmd == "log-groups":
                return run_cloudwatch_log_groups(args)
            if args.cloudwatch_cmd == "logs":
                return run_cloudwatch_logs(args)
            if args.cloudwatch_cmd == "metrics":
                return run_cloudwatch_metrics(args)
            if args.cloudwatch_cmd == "alarms":
                return run_cloudwatch_alarms(args)
            if args.cloudwatch_cmd == "events":
                return run_cloudwatch_events(args)
            if args.cloudwatch_cmd == "dashboards":
                return run_cloudwatch_dashboards(args)
            if args.cloudwatch_cmd == "all":
                return run_cloudwatch_all(args)
        
        if args.collect_target == "kms":
            from ventra.collector.kms.kms import run_kms
            return run_kms(args)
        
        if args.collect_target == "eventbridge":
            from ventra.collector.eventbridge.eventbridge_rules import run_eventbridge_rules
            from ventra.collector.eventbridge.eventbridge_targets import run_eventbridge_targets
            from ventra.collector.eventbridge.eventbridge_buses import run_eventbridge_buses
            from ventra.collector.eventbridge.eventbridge_all import run_eventbridge_all
            
            if args.eventbridge_cmd == "rules":
                return run_eventbridge_rules(args)
            if args.eventbridge_cmd == "targets":
                return run_eventbridge_targets(args)
            if args.eventbridge_cmd == "buses":
                return run_eventbridge_buses(args)
            if args.eventbridge_cmd == "all":
                return run_eventbridge_all(args)
        
        if args.collect_target == "lambda":
            import importlib
            lambda_functions = importlib.import_module("ventra.collector.lambda.lambda_functions")
            lambda_config = importlib.import_module("ventra.collector.lambda.lambda_config")
            lambda_env_vars = importlib.import_module("ventra.collector.lambda.lambda_env_vars")
            lambda_policy = importlib.import_module("ventra.collector.lambda.lambda_policy")
            lambda_code = importlib.import_module("ventra.collector.lambda.lambda_code")
            lambda_all = importlib.import_module("ventra.collector.lambda.lambda_all")
            
            if args.lambda_cmd == "functions":
                return lambda_functions.run_lambda_functions(args)
            if args.lambda_cmd == "config":
                return lambda_config.run_lambda_config(args)
            if args.lambda_cmd == "env-vars":
                return lambda_env_vars.run_lambda_env_vars(args)
            if args.lambda_cmd == "policy":
                return lambda_policy.run_lambda_policy(args)
            if args.lambda_cmd == "code":
                return lambda_code.run_lambda_code(args)
            if args.lambda_cmd == "all":
                return lambda_all.run_lambda_all(args)
        
        if args.collect_target == "dynamodb":
            from ventra.collector.dynamodb.dynamodb_tables import run_dynamodb_tables
            from ventra.collector.dynamodb.dynamodb_backups import run_dynamodb_backups
            from ventra.collector.dynamodb.dynamodb_streams import run_dynamodb_streams
            from ventra.collector.dynamodb.dynamodb_all import run_dynamodb_all
            
            if args.dynamodb_cmd == "tables":
                return run_dynamodb_tables(args)
            if args.dynamodb_cmd == "backups":
                return run_dynamodb_backups(args)
            if args.dynamodb_cmd == "streams":
                return run_dynamodb_streams(args)
            if args.dynamodb_cmd == "all":
                return run_dynamodb_all(args)
        
        if args.collect_target == "sns":
            from ventra.collector.sns.sns_topics import run_sns_topics
            from ventra.collector.sns.sns_subscriptions import run_sns_subscriptions
            from ventra.collector.sns.sns_all import run_sns_all
            
            if args.sns_cmd == "topics":
                return run_sns_topics(args)
            if args.sns_cmd == "subscriptions":
                return run_sns_subscriptions(args)
            if args.sns_cmd == "all":
                return run_sns_all(args)
        
        if args.collect_target == "sqs":
            from ventra.collector.sqs.sqs_queues import run_sqs_queues
            from ventra.collector.sqs.sqs_messages import run_sqs_messages
            from ventra.collector.sqs.sqs_all import run_sqs_all
            
            if args.sqs_cmd == "queues":
                return run_sqs_queues(args)
            if args.sqs_cmd == "messages":
                return run_sqs_messages(args)
            if args.sqs_cmd == "all":
                return run_sqs_all(args)
        
        if args.collect_target == "apigw":
            from ventra.collector.apigw.apigw_rest_apis import run_apigw_rest_apis
            from ventra.collector.apigw.apigw_routes import run_apigw_routes
            from ventra.collector.apigw.apigw_integrations import run_apigw_integrations
            from ventra.collector.apigw.apigw_all import run_apigw_all
            
            if args.apigw_cmd == "rest-apis":
                return run_apigw_rest_apis(args)
            if args.apigw_cmd == "routes":
                return run_apigw_routes(args)
            if args.apigw_cmd == "integrations":
                return run_apigw_integrations(args)
            if args.apigw_cmd == "all":
                return run_apigw_all(args)
        
        if args.collect_target == "elb":
            from ventra.collector.elb.elb_listeners import run_elb_listeners
            from ventra.collector.elb.elb_target_groups import run_elb_target_groups
            from ventra.collector.elb.elb_access_logs import run_elb_access_logs
            from ventra.collector.elb.elb_all import run_elb_all
            
            if args.elb_cmd == "listeners":
                return run_elb_listeners(args)
            if args.elb_cmd == "target-groups":
                return run_elb_target_groups(args)
            if args.elb_cmd == "access-logs":
                return run_elb_access_logs(args)
            if args.elb_cmd == "all":
                return run_elb_all(args)
        
        if args.collect_target == "route53":
            from ventra.collector.route53.route53_hosted_zones import run_route53_hosted_zones
            from ventra.collector.route53.route53_records import run_route53_records
            from ventra.collector.route53.route53_query_logs import run_route53_query_logs
            from ventra.collector.route53.route53_all import run_route53_all
            
            if args.route53_cmd == "hosted-zones":
                return run_route53_hosted_zones(args)
            if args.route53_cmd == "records":
                return run_route53_records(args)
            if args.route53_cmd == "query-logs":
                return run_route53_query_logs(args)
            if args.route53_cmd == "all":
                return run_route53_all(args)
        
        if args.collect_target == "eks":
            from ventra.collector.eks.eks_clusters import run_eks_clusters
            from ventra.collector.eks.eks_nodegroups import run_eks_nodegroups
            from ventra.collector.eks.eks_fargate import run_eks_fargate
            from ventra.collector.eks.eks_addons import run_eks_addons
            from ventra.collector.eks.eks_logs_config import run_eks_logs_config
            from ventra.collector.eks.eks_oidc import run_eks_oidc
            from ventra.collector.eks.eks_controlplane_logs import run_eks_controlplane_logs
            from ventra.collector.eks.eks_security import run_eks_security
            from ventra.collector.eks.eks_networking import run_eks_networking
            from ventra.collector.eks.eks_all import run_eks_all
            
            if args.eks_cmd == "clusters":
                return run_eks_clusters(args)
            if args.eks_cmd == "nodegroups":
                return run_eks_nodegroups(args)
            if args.eks_cmd == "fargate":
                return run_eks_fargate(args)
            if args.eks_cmd == "addons":
                return run_eks_addons(args)
            if args.eks_cmd == "logs-config":
                return run_eks_logs_config(args)
            if args.eks_cmd == "oidc":
                return run_eks_oidc(args)
            if args.eks_cmd == "controlplane-logs":
                return run_eks_controlplane_logs(args)
            if args.eks_cmd == "security":
                return run_eks_security(args)
            if args.eks_cmd == "networking":
                return run_eks_networking(args)
            if args.eks_cmd == "all":
                return run_eks_all(args)
        
        if args.collect_target == "config":
            from ventra.collector.config.config_history import run_config_history
            from ventra.collector.config.config_snapshots import run_config_snapshots
            from ventra.collector.config.config_drifts import run_config_drifts
            
            if args.config_cmd == "history":
                return run_config_history(args)
            if args.config_cmd == "snapshots":
                return run_config_snapshots(args)
            if args.config_cmd == "drifts":
                return run_config_drifts(args)
        
        if args.collect_target == "securityhub":
            from ventra.collector.securityhub.securityhub_findings import run_securityhub_findings
            
            if args.securityhub_cmd == "findings":
                return run_securityhub_findings(args)
            


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
    # NORMALIZE
    # =========================================================================
    normalize = sub.add_parser("normalize", help="Normalize collected data into standardized schema")
    normalize.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2')")
    normalize.add_argument("--normalizers", type=str, nargs="+", help="Specific normalizers to run (e.g., 'cloudtrail'). If omitted, runs all available normalizers")
    normalize.add_argument("--output-subdir", type=str, default="normalized", help="Output subdirectory within case directory (default: 'normalized')")
    normalize.add_argument("--profile", type=str, help="Ventra internal profile")
    normalize.add_argument("--account-id", type=str, help="AWS account ID (optional, will be extracted from data if available)")
    normalize.add_argument("--region", type=str, help="AWS region (optional, will be extracted from data if available)")

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

    # lake
    ct_lake = ct_sub.add_parser("lake")
    ct_lake.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ct_lake.add_argument("--sql", type=str, required=True, help="CloudTrail Lake SQL query to execute")
    ct_lake.add_argument("--output", type=str, help="Override output directory (defaults to case directory)")

    # all
    ct_all = ct_sub.add_parser("all")
    ct_all.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ct_all.add_argument("--hours", type=int, required=True)
    ct_all.add_argument("--bucket", type=str, required=True)
    ct_all.add_argument("--prefix", type=str, required=True)
    ct_all.add_argument("--output", type=str)

    # EC2
    ec2 = collect_sub.add_parser("ec2", help="EC2 collectors")
    ec2_sub = ec2.add_subparsers(dest="ec2_cmd", required=True)

    # metadata-passive
    ec2_meta = ec2_sub.add_parser("metadata-passive", help="Collect EC2 metadata passively via AWS APIs (non-intrusive)")
    ec2_meta.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ec2_meta.add_argument("--instance", type=str, required=True, help="EC2 instance ID(s), comma-separated (e.g., 'i-1234567890,i-0987654321')")
    ec2_meta.add_argument("--output", type=str, help="Override output directory (defaults to case directory)")

    # metadata-active
    ec2_active = ec2_sub.add_parser("metadata-active", help="Collect EC2 internal metadata via SSH + IMDS (requires running instance)")
    ec2_active.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ec2_active.add_argument("--instance", type=str, required=True, help="EC2 instance ID(s), comma-separated (e.g., 'i-1234567890,i-0987654321')")
    ec2_active.add_argument("--ssh-key", type=str, required=True, help="Path to SSH private key file (e.g., ~/.ssh/key.pem)")
    ec2_active.add_argument("--ssh-user", type=str, help="SSH username (defaults to 'ec2-user' for Amazon Linux, 'ubuntu' for Ubuntu)")
    ec2_active.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    ec2_active.add_argument("--output", type=str, help="Override output directory (defaults to case directory)")

    # volumes
    ec2_volumes = ec2_sub.add_parser("volumes", help="Collect EBS volume metadata and automatically extract forensic artifacts")
    ec2_volumes.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ec2_volumes.add_argument("--instance", type=str, help="EC2 instance ID - collect all volumes attached to this instance (e.g., 'i-1234567890')")
    ec2_volumes.add_argument("--volume", type=str, help="Specific volume ID to collect (e.g., 'vol-1234567890abcdef0')")
    ec2_volumes.add_argument("--volumes", type=str, help="Comma-separated volume IDs (e.g., 'vol-123,vol-456')")
    ec2_volumes.add_argument("--output", type=str, help="Override output directory (defaults to case directory)")

    # snapshots
    ec2_snapshots = ec2_sub.add_parser("snapshots", help="Create snapshots from instance volumes OR collect metadata for existing snapshots. Automatically extracts forensic artifacts.")
    ec2_snapshots.add_argument("--case", type=str, required=True, help="Case name (e.g., 'ec2-compromise' or 'ec2'). Creates case if it doesn't exist.")
    ec2_snapshots.add_argument("--instance", type=str, help="EC2 instance ID - create new snapshots from all volumes attached to this instance (e.g., 'i-1234567890')")
    ec2_snapshots.add_argument("--snapshot", type=str, help="Specific snapshot ID to collect metadata for (e.g., 'snap-1234567890abcdef0')")
    ec2_snapshots.add_argument("--snapshots", type=str, help="Comma-separated snapshot IDs to collect metadata for (e.g., 'snap-123,snap-456')")
    ec2_snapshots.add_argument("--output", type=str, help="Override output directory (defaults to case directory)")
    
    ec2_all = ec2_sub.add_parser("all", help="Collect all EC2 instance data (metadata, volumes, snapshots) into one file")
    ec2_all.add_argument("--case", type=str, required=True, help="Case name")
    ec2_all.add_argument("--instance", type=str, required=True, help="EC2 instance ID")
    ec2_all.add_argument("--output", type=str, help="Override output directory")

    # VPC
    vpc = collect_sub.add_parser("vpc", help="VPC network infrastructure collectors")
    vpc_sub = vpc.add_subparsers(dest="vpc_cmd", required=True)
    
    # info
    vpc_info = vpc_sub.add_parser("info", help="Collect VPC information (VPCs, CIDR blocks, DNS/DHCP options)")
    vpc_info.add_argument("--case", type=str, required=True, help="Case name")
    vpc_info.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_info.add_argument("--output", type=str, help="Override output directory")
    
    # subnets
    vpc_subnets = vpc_sub.add_parser("subnets", help="Collect VPC subnet information")
    vpc_subnets.add_argument("--case", type=str, required=True, help="Case name")
    vpc_subnets.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_subnets.add_argument("--output", type=str, help="Override output directory")
    
    # routes
    vpc_routes = vpc_sub.add_parser("routes", help="Collect VPC route table information")
    vpc_routes.add_argument("--case", type=str, required=True, help="Case name")
    vpc_routes.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_routes.add_argument("--output", type=str, help="Override output directory")
    
    # sg (security groups)
    vpc_sg = vpc_sub.add_parser("sg", help="Collect VPC security group information")
    vpc_sg.add_argument("--case", type=str, required=True, help="Case name")
    vpc_sg.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_sg.add_argument("--output", type=str, help="Override output directory")
    
    # nacl
    vpc_nacl = vpc_sub.add_parser("nacl", help="Collect VPC network ACL information")
    vpc_nacl.add_argument("--case", type=str, required=True, help="Case name")
    vpc_nacl.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_nacl.add_argument("--output", type=str, help="Override output directory")
    
    # endpoints
    vpc_endpoints = vpc_sub.add_parser("endpoints", help="Collect VPC endpoint information")
    vpc_endpoints.add_argument("--case", type=str, required=True, help="Case name")
    vpc_endpoints.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_endpoints.add_argument("--output", type=str, help="Override output directory")
    
    # igw
    vpc_igw = vpc_sub.add_parser("igw", help="Collect internet gateway information")
    vpc_igw.add_argument("--case", type=str, required=True, help="Case name")
    vpc_igw.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_igw.add_argument("--output", type=str, help="Override output directory")
    
    # nat
    vpc_nat = vpc_sub.add_parser("nat", help="Collect NAT gateway information")
    vpc_nat.add_argument("--case", type=str, required=True, help="Case name")
    vpc_nat.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_nat.add_argument("--output", type=str, help="Override output directory")
    
    # flowlogs
    vpc_flowlogs = vpc_sub.add_parser("flowlogs", help="Collect VPC flow log configurations and optionally recent log events")
    vpc_flowlogs.add_argument("--case", type=str, required=True, help="Case name")
    vpc_flowlogs.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_flowlogs.add_argument("--hours", type=int, help="Retrieve last N hours of CloudWatch Logs events (optional)")
    vpc_flowlogs.add_argument("--output", type=str, help="Override output directory")
    
    # all
    vpc_all = vpc_sub.add_parser("all", help="Run all VPC collectors in sequence")
    vpc_all.add_argument("--case", type=str, required=True, help="Case name")
    vpc_all.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_all.add_argument("--hours", type=int, help="Retrieve last N hours of CloudWatch Logs events for flow logs (optional)")
    vpc_all.add_argument("--output", type=str, help="Override output directory")

    # IAM
    iam = collect_sub.add_parser("iam", help="IAM collectors")
    iam_sub = iam.add_subparsers(dest="iam_cmd", required=True)
    
    # all (full account collection)
    iam_all = iam_sub.add_parser("all", help="Collect comprehensive IAM information for entire account")
    iam_all.add_argument("--case", type=str, required=True, help="Case name")
    iam_all.add_argument("--output", type=str, help="Override output directory")
    
    # user (single user)
    iam_user = iam_sub.add_parser("user", help="Collect detailed IAM information for a specific user")
    iam_user.add_argument("--case", type=str, required=True, help="Case name")
    iam_user.add_argument("--name", type=str, required=True, help="IAM username (e.g., 'alice')")
    iam_user.add_argument("--output", type=str, help="Override output directory")
    
    # role (single role)
    iam_role = iam_sub.add_parser("role", help="Collect detailed IAM information for a specific role")
    iam_role.add_argument("--case", type=str, required=True, help="Case name")
    iam_role.add_argument("--name", type=str, required=True, help="IAM role name")
    iam_role.add_argument("--output", type=str, help="Override output directory")
    
    # group (single group)
    iam_group = iam_sub.add_parser("group", help="Collect detailed IAM information for a specific group")
    iam_group.add_argument("--case", type=str, required=True, help="Case name")
    iam_group.add_argument("--name", type=str, required=True, help="IAM group name")
    iam_group.add_argument("--output", type=str, help="Override output directory")
    
    # policy (single policy)
    iam_policy = iam_sub.add_parser("policy", help="Collect detailed IAM information for a specific managed policy")
    iam_policy.add_argument("--case", type=str, required=True, help="Case name")
    iam_policy.add_argument("--arn", type=str, required=True, help="IAM policy ARN")
    iam_policy.add_argument("--output", type=str, help="Override output directory")

    # S3
    s3 = collect_sub.add_parser("s3", help="S3 collectors")
    s3_sub = s3.add_subparsers(dest="s3_cmd", required=True)
    
    # bucket-info
    s3_bucket_info = s3_sub.add_parser("bucket-info", help="Bucket metadata, ACL, policy, encryption, object-lock, lifecycle, replication, CORS, website config")
    s3_bucket_info.add_argument("--case", type=str, required=True, help="Case name")
    s3_bucket_info.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_bucket_info.add_argument("--output", type=str, help="Override output directory")
    
    # access
    s3_access = s3_sub.add_parser("access", help="Access points, access-point policies, cross-account principals, public exposure checks")
    s3_access.add_argument("--case", type=str, required=True, help="Case name")
    s3_access.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_access.add_argument("--output", type=str, help="Override output directory")
    
    # objects
    s3_objects = s3_sub.add_parser("objects", help="Lightweight listing (NOT downloading everything). Recursively lists all objects under prefix")
    s3_objects.add_argument("--case", type=str, required=True, help="Case name")
    s3_objects.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_objects.add_argument("--prefix", type=str, help="Prefix to list objects under (recursive)")
    s3_objects.add_argument("--limit", type=int, help="Limit number of objects to list (optional)")
    s3_objects.add_argument("--output", type=str, help="Override output directory")
    
    # versions
    s3_versions = s3_sub.add_parser("versions", help="List all versions and delete-markers (if versioning enabled). Extremely valuable in breach investigations")
    s3_versions.add_argument("--case", type=str, required=True, help="Case name")
    s3_versions.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_versions.add_argument("--prefix", type=str, help="Prefix to filter versions (optional)")
    s3_versions.add_argument("--output", type=str, help="Override output directory")
    
    # all
    s3_all = s3_sub.add_parser("all", help="Run all S3 collectors for a bucket")
    s3_all.add_argument("--case", type=str, required=True, help="Case name")
    s3_all.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_all.add_argument("--prefix", type=str, help="Prefix for objects/versions collection (optional)")
    s3_all.add_argument("--output", type=str, help="Override output directory")

    # GuardDuty
    guradduty = collect_sub.add_parser("guradduty", help="GuardDuty collectors")
    guradduty_sub = guradduty.add_subparsers(dest="guradduty_cmd", required=True)
    
    # detectors
    gd_detectors = guradduty_sub.add_parser("detectors", help="Collect all GuardDuty detectors")
    gd_detectors.add_argument("--case", type=str, required=True, help="Case name")
    gd_detectors.add_argument("--all-regions", action="store_true", help="Collect from all regions")
    gd_detectors.add_argument("--output", type=str, help="Override output directory")
    
    # findings
    gd_findings = guradduty_sub.add_parser("findings", help="Collect GuardDuty findings")
    gd_findings.add_argument("--case", type=str, required=True, help="Case name")
    gd_findings.add_argument("--severity", type=str, help="Filter by severity (low, medium, high, critical)")
    gd_findings.add_argument("--resource", type=str, help="Filter by resource ID (e.g., i-1234)")
    gd_findings.add_argument("--output", type=str, help="Override output directory")
    
    # details
    gd_details = guradduty_sub.add_parser("details", help="Collect detailed information for a specific finding")
    gd_details.add_argument("--case", type=str, required=True, help="Case name")
    gd_details.add_argument("--id", type=str, required=True, help="Finding ID")
    gd_details.add_argument("--output", type=str, help="Override output directory")
    
    # malware
    gd_malware = guradduty_sub.add_parser("malware", help="Collect EBS malware-scan results")
    gd_malware.add_argument("--case", type=str, required=True, help="Case name")
    gd_malware.add_argument("--output", type=str, help="Override output directory")
    
    # all
    gd_all = guradduty_sub.add_parser("all", help="Run all GuardDuty collectors")
    gd_all.add_argument("--case", type=str, required=True, help="Case name")
    gd_all.add_argument("--all-regions", action="store_true", help="Collect from all regions for detectors")
    gd_all.add_argument("--output", type=str, help="Override output directory")

    # CloudWatch
    cloudwatch = collect_sub.add_parser("cloudwatch", help="CloudWatch collectors")
    cw_sub = cloudwatch.add_subparsers(dest="cloudwatch_cmd", required=True)
    
    # log-groups
    cw_log_groups = cw_sub.add_parser("log-groups", help="Collect all CloudWatch log groups")
    cw_log_groups.add_argument("--case", type=str, required=True, help="Case name")
    cw_log_groups.add_argument("--output", type=str, help="Override output directory")
    
    # logs
    cw_logs = cw_sub.add_parser("logs", help="Collect log events from a specific log group")
    cw_logs.add_argument("--case", type=str, required=True, help="Case name")
    cw_logs.add_argument("--group", type=str, required=True, help="Log group name")
    cw_logs.add_argument("--hours", type=int, help="Collect events from last N hours (optional)")
    cw_logs.add_argument("--output", type=str, help="Override output directory")
    
    # metrics
    cw_metrics = cw_sub.add_parser("metrics", help="Collect CloudWatch metrics")
    cw_metrics.add_argument("--case", type=str, required=True, help="Case name")
    cw_metrics.add_argument("--namespace", type=str, help="Filter by namespace (optional)")
    cw_metrics.add_argument("--dimensions", type=str, help="Filter by dimensions (format: Name1=Value1,Name2=Value2)")
    cw_metrics.add_argument("--hours", type=int, default=24, help="Hours of metric data to collect (default: 24)")
    cw_metrics.add_argument("--output", type=str, help="Override output directory")
    
    # alarms
    cw_alarms = cw_sub.add_parser("alarms", help="Collect CloudWatch alarms")
    cw_alarms.add_argument("--case", type=str, required=True, help="Case name")
    cw_alarms.add_argument("--output", type=str, help="Override output directory")
    
    # events
    cw_events = cw_sub.add_parser("events", help="Collect EventBridge rules")
    cw_events.add_argument("--case", type=str, required=True, help="Case name")
    cw_events.add_argument("--output", type=str, help="Override output directory")
    
    # dashboards
    cw_dashboards = cw_sub.add_parser("dashboards", help="Collect CloudWatch dashboards")
    cw_dashboards.add_argument("--case", type=str, required=True, help="Case name")
    cw_dashboards.add_argument("--output", type=str, help="Override output directory")
    
    # all
    cw_all = cw_sub.add_parser("all", help="Run all CloudWatch collectors")
    cw_all.add_argument("--case", type=str, required=True, help="Case name")
    cw_all.add_argument("--output", type=str, help="Override output directory")

    # KMS
    kms = collect_sub.add_parser("kms", help="KMS collectors")
    kms.add_argument("--case", type=str, required=True, help="Case name")
    kms.add_argument("--output", type=str, help="Override output directory")

    # EventBridge
    eventbridge = collect_sub.add_parser("eventbridge", help="EventBridge collectors")
    eventbridge_sub = eventbridge.add_subparsers(dest="eventbridge_cmd", required=True)
    
    eb_rules = eventbridge_sub.add_parser("rules", help="Collect EventBridge rules")
    eb_rules.add_argument("--case", type=str, required=True, help="Case name")
    eb_rules.add_argument("--output", type=str, help="Override output directory")
    
    eb_targets = eventbridge_sub.add_parser("targets", help="Collect EventBridge rule targets")
    eb_targets.add_argument("--case", type=str, required=True, help="Case name")
    eb_targets.add_argument("--output", type=str, help="Override output directory")
    
    eb_buses = eventbridge_sub.add_parser("buses", help="Collect EventBridge event buses")
    eb_buses.add_argument("--case", type=str, required=True, help="Case name")
    eb_buses.add_argument("--output", type=str, help="Override output directory")
    
    eb_all = eventbridge_sub.add_parser("all", help="Run all EventBridge collectors")
    eb_all.add_argument("--case", type=str, required=True, help="Case name")
    eb_all.add_argument("--output", type=str, help="Override output directory")

    # Lambda
    lambda_parser = collect_sub.add_parser("lambda", help="Lambda collectors")
    lambda_sub = lambda_parser.add_subparsers(dest="lambda_cmd", required=True)
    
    lambda_functions = lambda_sub.add_parser("functions", help="Collect all Lambda functions")
    lambda_functions.add_argument("--case", type=str, required=True, help="Case name")
    lambda_functions.add_argument("--output", type=str, help="Override output directory")
    
    lambda_config = lambda_sub.add_parser("config", help="Collect Lambda function configuration")
    lambda_config.add_argument("--case", type=str, required=True, help="Case name")
    lambda_config.add_argument("--name", type=str, required=True, help="Function name")
    lambda_config.add_argument("--output", type=str, help="Override output directory")
    
    lambda_env_vars = lambda_sub.add_parser("env-vars", help="Collect Lambda environment variables")
    lambda_env_vars.add_argument("--case", type=str, required=True, help="Case name")
    lambda_env_vars.add_argument("--name", type=str, required=True, help="Function name")
    lambda_env_vars.add_argument("--output", type=str, help="Override output directory")
    
    lambda_policy = lambda_sub.add_parser("policy", help="Collect Lambda resource-based policy")
    lambda_policy.add_argument("--case", type=str, required=True, help="Case name")
    lambda_policy.add_argument("--name", type=str, required=True, help="Function name")
    lambda_policy.add_argument("--output", type=str, help="Override output directory")
    
    lambda_code = lambda_sub.add_parser("code", help="Download Lambda function code (ZIP)")
    lambda_code.add_argument("--case", type=str, required=True, help="Case name")
    lambda_code.add_argument("--name", type=str, required=True, help="Function name")
    lambda_code.add_argument("--output", type=str, help="Override output directory")
    
    lambda_all = lambda_sub.add_parser("all", help="Collect all Lambda function data (config, env vars, policy, code metadata)")
    lambda_all.add_argument("--case", type=str, required=True, help="Case name")
    lambda_all.add_argument("--name", type=str, required=True, help="Function name or ARN")
    lambda_all.add_argument("--output", type=str, help="Override output directory")

    # DynamoDB
    dynamodb = collect_sub.add_parser("dynamodb", help="DynamoDB collectors")
    dynamodb_sub = dynamodb.add_subparsers(dest="dynamodb_cmd", required=True)
    
    ddb_tables = dynamodb_sub.add_parser("tables", help="Collect DynamoDB tables")
    ddb_tables.add_argument("--case", type=str, required=True, help="Case name")
    ddb_tables.add_argument("--output", type=str, help="Override output directory")
    
    ddb_backups = dynamodb_sub.add_parser("backups", help="Collect DynamoDB backups")
    ddb_backups.add_argument("--case", type=str, required=True, help="Case name")
    ddb_backups.add_argument("--output", type=str, help="Override output directory")
    
    ddb_streams = dynamodb_sub.add_parser("streams", help="Collect DynamoDB streams")
    ddb_streams.add_argument("--case", type=str, required=True, help="Case name")
    ddb_streams.add_argument("--output", type=str, help="Override output directory")
    
    ddb_all = dynamodb_sub.add_parser("all", help="Collect all DynamoDB data for a table (table info, attributes, items, backups, streams, and exports)")
    ddb_all.add_argument("--case", type=str, required=True, help="Case name")
    ddb_all.add_argument("--table", type=str, required=True, help="Table name or ARN")
    ddb_all.add_argument("--limit", type=int, help="Limit number of table items to scan (optional, scans all items if not provided)")
    ddb_all.add_argument("--output", type=str, help="Override output directory")

    # SNS
    sns = collect_sub.add_parser("sns", help="SNS collectors")
    sns_sub = sns.add_subparsers(dest="sns_cmd", required=True)
    
    sns_topics = sns_sub.add_parser("topics", help="Collect SNS topics")
    sns_topics.add_argument("--case", type=str, required=True, help="Case name")
    sns_topics.add_argument("--output", type=str, help="Override output directory")
    
    sns_subscriptions = sns_sub.add_parser("subscriptions", help="Collect SNS subscriptions")
    sns_subscriptions.add_argument("--case", type=str, required=True, help="Case name")
    sns_subscriptions.add_argument("--output", type=str, help="Override output directory")
    
    sns_all = sns_sub.add_parser("all", help="Collect all SNS data (topics and subscriptions) into one file")
    sns_all.add_argument("--case", type=str, required=True, help="Case name")
    sns_all.add_argument("--output", type=str, help="Override output directory")

    # SQS
    sqs = collect_sub.add_parser("sqs", help="SQS collectors")
    sqs_sub = sqs.add_subparsers(dest="sqs_cmd", required=True)
    
    sqs_queues = sqs_sub.add_parser("queues", help="Collect SQS queues")
    sqs_queues.add_argument("--case", type=str, required=True, help="Case name")
    sqs_queues.add_argument("--output", type=str, help="Override output directory")
    
    sqs_messages = sqs_sub.add_parser("messages", help="Collect sample SQS messages")
    sqs_messages.add_argument("--case", type=str, required=True, help="Case name")
    sqs_messages.add_argument("--queue", type=str, help="Specific queue URL (optional, samples all if not provided)")
    sqs_messages.add_argument("--sample", action="store_true", default=True, help="Sample mode (default: True)")
    sqs_messages.add_argument("--output", type=str, help="Override output directory")
    
    sqs_all = sqs_sub.add_parser("all", help="Collect all SQS data (queues and sample messages) into one file")
    sqs_all.add_argument("--case", type=str, required=True, help="Case name")
    sqs_all.add_argument("--output", type=str, help="Override output directory")

    # API Gateway
    apigw = collect_sub.add_parser("apigw", help="API Gateway collectors")
    apigw_sub = apigw.add_subparsers(dest="apigw_cmd", required=True)
    
    apigw_rest_apis = apigw_sub.add_parser("rest-apis", help="Collect REST APIs")
    apigw_rest_apis.add_argument("--case", type=str, required=True, help="Case name")
    apigw_rest_apis.add_argument("--output", type=str, help="Override output directory")
    
    apigw_routes = apigw_sub.add_parser("routes", help="Collect API routes")
    apigw_routes.add_argument("--case", type=str, required=True, help="Case name")
    apigw_routes.add_argument("--api-id", type=str, help="Specific API ID (optional, collects all if not provided)")
    apigw_routes.add_argument("--output", type=str, help="Override output directory")
    
    apigw_integrations = apigw_sub.add_parser("integrations", help="Collect API integrations")
    apigw_integrations.add_argument("--case", type=str, required=True, help="Case name")
    apigw_integrations.add_argument("--api-id", type=str, help="Specific API ID (optional, collects all if not provided)")
    apigw_integrations.add_argument("--output", type=str, help="Override output directory")
    
    apigw_all = apigw_sub.add_parser("all", help="Collect all API Gateway data (REST APIs, routes, and integrations)")
    apigw_all.add_argument("--case", type=str, required=True, help="Case name")
    apigw_all.add_argument("--api-id", type=str, help="Specific API ID (optional, collects all APIs if not provided)")
    apigw_all.add_argument("--output", type=str, help="Override output directory")

    # ELB
    elb = collect_sub.add_parser("elb", help="ELB collectors")
    elb_sub = elb.add_subparsers(dest="elb_cmd", required=True)
    
    elb_listeners = elb_sub.add_parser("listeners", help="Collect load balancer listeners")
    elb_listeners.add_argument("--case", type=str, required=True, help="Case name")
    elb_listeners.add_argument("--output", type=str, help="Override output directory")
    
    elb_target_groups = elb_sub.add_parser("target-groups", help="Collect target groups")
    elb_target_groups.add_argument("--case", type=str, required=True, help="Case name")
    elb_target_groups.add_argument("--output", type=str, help="Override output directory")
    
    elb_access_logs = elb_sub.add_parser("access-logs", help="Collect access log configurations")
    elb_access_logs.add_argument("--case", type=str, required=True, help="Case name")
    elb_access_logs.add_argument("--output", type=str, help="Override output directory")
    
    elb_all = elb_sub.add_parser("all", help="Collect all ELB data (listeners, target groups, access logs)")
    elb_all.add_argument("--case", type=str, required=True, help="Case name")
    elb_all.add_argument("--output", type=str, help="Override output directory")

    # Route53
    route53 = collect_sub.add_parser("route53", help="Route53 collectors")
    route53_sub = route53.add_subparsers(dest="route53_cmd", required=True)
    
    r53_hosted_zones = route53_sub.add_parser("hosted-zones", help="Collect hosted zones")
    r53_hosted_zones.add_argument("--case", type=str, required=True, help="Case name")
    r53_hosted_zones.add_argument("--output", type=str, help="Override output directory")
    
    r53_records = route53_sub.add_parser("records", help="Collect DNS records")
    r53_records.add_argument("--case", type=str, required=True, help="Case name")
    r53_records.add_argument("--zone-id", type=str, help="Specific zone ID (optional, collects all if not provided)")
    r53_records.add_argument("--output", type=str, help="Override output directory")
    
    r53_query_logs = route53_sub.add_parser("query-logs", help="Collect query logging configurations")
    r53_query_logs.add_argument("--case", type=str, required=True, help="Case name")
    r53_query_logs.add_argument("--output", type=str, help="Override output directory")
    
    r53_all = route53_sub.add_parser("all", help="Collect all Route53 data for a hosted zone (zone info, records, query logs) into one file")
    r53_all.add_argument("--case", type=str, required=True, help="Case name")
    r53_all.add_argument("--zone", type=str, required=True, help="Zone ID or domain name")
    r53_all.add_argument("--output", type=str, help="Override output directory")

    # EKS
    eks = collect_sub.add_parser("eks", help="EKS collectors")
    eks_sub = eks.add_subparsers(dest="eks_cmd", required=True)
    
    eks_clusters = eks_sub.add_parser("clusters", help="Collect EKS clusters")
    eks_clusters.add_argument("--case", type=str, required=True, help="Case name")
    eks_clusters.add_argument("--output", type=str, help="Override output directory")
    
    eks_nodegroups = eks_sub.add_parser("nodegroups", help="Collect nodegroups")
    eks_nodegroups.add_argument("--case", type=str, required=True, help="Case name")
    eks_nodegroups.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_nodegroups.add_argument("--output", type=str, help="Override output directory")
    
    eks_fargate = eks_sub.add_parser("fargate", help="Collect Fargate profiles")
    eks_fargate.add_argument("--case", type=str, required=True, help="Case name")
    eks_fargate.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_fargate.add_argument("--output", type=str, help="Override output directory")
    
    eks_addons = eks_sub.add_parser("addons", help="Collect addons")
    eks_addons.add_argument("--case", type=str, required=True, help="Case name")
    eks_addons.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_addons.add_argument("--output", type=str, help="Override output directory")
    
    eks_logs_config = eks_sub.add_parser("logs-config", help="Collect logging configuration")
    eks_logs_config.add_argument("--case", type=str, required=True, help="Case name")
    eks_logs_config.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_logs_config.add_argument("--output", type=str, help="Override output directory")
    
    eks_oidc = eks_sub.add_parser("oidc", help="Collect OIDC configuration")
    eks_oidc.add_argument("--case", type=str, required=True, help="Case name")
    eks_oidc.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_oidc.add_argument("--output", type=str, help="Override output directory")
    
    eks_controlplane_logs = eks_sub.add_parser("controlplane-logs", help="Collect control plane logs")
    eks_controlplane_logs.add_argument("--case", type=str, required=True, help="Case name")
    eks_controlplane_logs.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_controlplane_logs.add_argument("--hours", type=int, default=24, help="Hours of logs to collect (default: 24)")
    eks_controlplane_logs.add_argument("--output", type=str, help="Override output directory")
    
    eks_security = eks_sub.add_parser("security", help="Collect security configuration")
    eks_security.add_argument("--case", type=str, required=True, help="Case name")
    eks_security.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_security.add_argument("--output", type=str, help="Override output directory")
    
    eks_networking = eks_sub.add_parser("networking", help="Collect networking configuration")
    eks_networking.add_argument("--case", type=str, required=True, help="Case name")
    eks_networking.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_networking.add_argument("--output", type=str, help="Override output directory")
    
    eks_all = eks_sub.add_parser("all", help="Run all EKS collectors")
    eks_all.add_argument("--case", type=str, required=True, help="Case name")
    eks_all.add_argument("--cluster", type=str, required=True, help="Cluster name")
    eks_all.add_argument("--hours", type=int, default=24, help="Hours of control plane logs to collect (default: 24)")
    eks_all.add_argument("--output", type=str, help="Override output directory")

    # Config
    config = collect_sub.add_parser("config", help="AWS Config collectors")
    config_sub = config.add_subparsers(dest="config_cmd", required=True)
    
    config_history = config_sub.add_parser("history", help="Collect configuration history")
    config_history.add_argument("--case", type=str, required=True, help="Case name")
    config_history.add_argument("--resource-type", type=str, help="Filter by resource type (optional)")
    config_history.add_argument("--resource-id", type=str, help="Filter by resource ID (optional)")
    config_history.add_argument("--hours", type=int, default=24, help="Hours of history to collect (default: 24)")
    config_history.add_argument("--output", type=str, help="Override output directory")
    
    config_snapshots = config_sub.add_parser("snapshots", help="Collect configuration snapshots")
    config_snapshots.add_argument("--case", type=str, required=True, help="Case name")
    config_snapshots.add_argument("--output", type=str, help="Override output directory")
    
    config_drifts = config_sub.add_parser("drifts", help="Collect configuration drifts")
    config_drifts.add_argument("--case", type=str, required=True, help="Case name")
    config_drifts.add_argument("--output", type=str, help="Override output directory")

    # Security Hub
    securityhub = collect_sub.add_parser("securityhub", help="Security Hub collectors")
    securityhub_sub = securityhub.add_subparsers(dest="securityhub_cmd", required=True)
    
    sh_findings = securityhub_sub.add_parser("findings", help="Collect Security Hub findings")
    sh_findings.add_argument("--case", type=str, required=True, help="Case name")
    sh_findings.add_argument("--severity", type=str, help="Filter by severity (low, medium, high, critical)")
    sh_findings.add_argument("--compliance-status", type=str, help="Filter by compliance status (passed, failed, warning)")
    sh_findings.add_argument("--output", type=str, help="Override output directory")

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