#!/usr/bin/env python3

import argparse
import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.markdown import Markdown
from rich.syntax import Syntax

from ventra.auth.whoami import aws_whoami
from ventra.auth.store import save_ventra_profile
from ventra.collector.events.cloudtrail_history import run_cloudtrail_history
from ventra.collector.events.cloudtrail_s3 import run_cloudtrail_s3
from ventra.collector.events.cloudtrail_lake import run_cloudtrail_lake
from ventra.collector.resources.ec2.ec2_metadata_passive import run_ec2_meta_external
from ventra.case.store import create_case, list_cases, get_or_create_case

console = Console(highlight=True, force_terminal=True)


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
        console.print(Panel.fit(
            "[bold green]🔐 Configuring AWS Profile[/bold green]",
            border_style="green",
            box=box.ROUNDED
        ))
        console.print()
        
        # Validate credentials
        with console.status("[bold cyan]Validating credentials...[/bold cyan]", spinner="dots"):
            try:
                session = boto3.Session(
                    aws_access_key_id=args.access_key,
                    aws_secret_access_key=args.secret_key,
                    region_name=args.region,
                )
                sts = session.client("sts")
                identity = sts.get_caller_identity()
                
                account_id = identity.get('Account', 'N/A')
                arn = identity.get('Arn', 'N/A')
                user_id = identity.get('UserId', 'N/A')
                
                console.print(f"[green]✓[/green] [bold]Credentials validated successfully![/bold]")
                console.print()
                
                from rich.table import Table
                auth_table = Table(show_header=False, box=box.ROUNDED, border_style="green")
                auth_table.add_column("Field", style="cyan", width=15)
                auth_table.add_column("Value", style="yellow")
                
                auth_table.add_row("Account ID", f"[bold]{account_id}[/bold]")
                auth_table.add_row("User ID", user_id)
                auth_table.add_row("ARN", arn)
                auth_table.add_row("Region", f"[bold]{args.region}[/bold]")
                
                console.print(auth_table)
                console.print()
                
            except ClientError as e:
                console.print(f"[red]❌[/red] [bold red]Invalid AWS credentials[/bold red]")
                console.print(f"[dim]{e}[/dim]")
                return

        save_ventra_profile(
            profile=args.profile,
            access_key=args.access_key,
            secret_key=args.secret_key,
            region=args.region,
        )
        
        console.print(Panel.fit(
            f"[green]✓[/green] Profile [bold cyan]'{args.profile}'[/bold cyan] saved successfully",
            border_style="green",
            box=box.ROUNDED
        ))
        return

    # -------------------------------------------------------------------------
    # WHOAMI
    # -------------------------------------------------------------------------
    if args.command == "whoami":
        console.print(Panel.fit(
            "[bold cyan]🔍 AWS Identity Check[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED
        ))
        console.print()
        
        with console.status("[bold cyan]Fetching identity...[/bold cyan]", spinner="dots"):
            info = aws_whoami(args.profile)

        if "error" in info:
            console.print(Panel.fit(
                f"[red]❌ Error:[/red] {info['error']}",
                border_style="red",
                box=box.ROUNDED
            ))
            return

        from rich.table import Table
        table = Table(
            title="[bold cyan]👤 AWS Identity[/bold cyan]",
            box=box.ROUNDED,
            show_header=False,
            border_style="cyan"
        )
        table.add_column("Field", style="cyan", width=15, no_wrap=True)
        table.add_column("Value", style="yellow")
        
        table.add_row("📋 Profile", f"[bold]{info.get('Profile', 'N/A')}[/bold]")
        table.add_row("🏢 Account", f"[bold green]{info.get('Account', 'N/A')}[/bold green]")
        table.add_row("🌍 Region", f"[bold]{info.get('Region', 'N/A')}[/bold]")
        table.add_row("🆔 User ID", info.get('UserId', 'N/A'))
        table.add_row("🔗 ARN", f"[dim]{info.get('Arn', 'N/A')}[/dim]")
        
        console.print(table)
        console.print()
        return

    # -------------------------------------------------------------------------
    # CASE
    # -------------------------------------------------------------------------
    if args.command == "case":
        if args.case_cmd == "new":
            console.print(Panel.fit(
                "[bold yellow]📁 Creating New Case[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED
            ))
            console.print()
            
            with console.status("[bold yellow]Creating case...[/bold yellow]", spinner="dots"):
                case_name, case_dir = create_case(args.name)
            
            console.print(Panel.fit(
                f"[green]✓[/green] Case [bold cyan]{case_name}[/bold cyan] created successfully!\n"
                f"[dim]Directory: {case_dir}[/dim]",
                border_style="green",
                box=box.ROUNDED
            ))
            return
        
        if args.case_cmd == "list":
            console.print(Panel.fit(
                "[bold yellow]📋 Listing Cases[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED
            ))
            console.print()
            
            cases = list_cases()
            if not cases:
                console.print(Panel.fit(
                    "[yellow]⚠ No cases found[/yellow]",
                    border_style="yellow",
                    box=box.ROUNDED
                ))
                return
            
            from rich.table import Table
            table = Table(
                title="[bold yellow]📁 Cases[/bold yellow]",
                box=box.ROUNDED,
                border_style="yellow",
                show_lines=True
            )
            table.add_column("#", style="dim", width=4, justify="right")
            table.add_column("Case Name", style="cyan", width=30)
            table.add_column("Directory", style="dim")
            
            for idx, (case_name, case_dir) in enumerate(cases.items(), 1):
                table.add_row(str(idx), case_name, case_dir)
            
            console.print(table)
            console.print()
            return

    # -------------------------------------------------------------------------
    # STATUS
    # -------------------------------------------------------------------------
    if args.command == "status":
        if args.status_cmd == "collectors":
            from ventra.status.collectors import check_collector_status, format_status_table
            
            console.print(Panel.fit(
                "[bold magenta]📊 Collector Status Check[/bold magenta]",
                border_style="magenta",
                box=box.ROUNDED
            ))
            console.print()
            
            with console.status("[bold magenta]Analyzing collectors...[/bold magenta]", spinner="dots"):
                case_names = getattr(args, "cases", None)
                status = check_collector_status(case_names)
            
            table = format_status_table(status, case_names)
            console.print(table)
            console.print()
            return

    # -------------------------------------------------------------------------
    # NORMALIZE
    # -------------------------------------------------------------------------
    if args.command == "normalize":
        from ventra.case.store import get_case_dir
        from ventra.normalization import run_from_args
        
        console.print(Panel.fit(
            "[bold blue]🔄 Normalizing Collected Data[/bold blue]",
            border_style="blue",
            box=box.ROUNDED
        ))
        console.print()
        
        # Resolve case directory
        case_identifier = args.case
        case_dir = get_case_dir(case_identifier)
        
        if not case_dir:
            console.print(Panel.fit(
                f"[red]❌ Case not found:[/red] [bold]{case_identifier}[/bold]\n"
                "[dim]Use 'ventra case list' to see available cases[/dim]",
                border_style="red",
                box=box.ROUNDED
            ))
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
            
            # Print summary with Rich
            console.print()
            from rich.table import Table
            summary_table = Table(
                title="[bold blue]📊 Normalization Summary[/bold blue]",
                box=box.ROUNDED,
                border_style="blue",
                show_lines=True
            )
            summary_table.add_column("Status", style="bold", width=8, justify="center")
            summary_table.add_column("Normalizer", style="cyan", width=25)
            summary_table.add_column("Records", style="yellow", justify="right", width=12)
            summary_table.add_column("Errors", style="red", justify="right", width=10)
            summary_table.add_column("Output", style="dim")
            
            total_records = 0
            total_errors = 0
            
            for summary in summaries:
                status_icon = "[green]✓[/green]" if summary.error_count == 0 else "[yellow]⚠[/yellow]"
                error_style = "" if summary.error_count == 0 else "[bold red]"
                total_records += summary.record_count
                total_errors += summary.error_count
                
                summary_table.add_row(
                    status_icon,
                    summary.name,
                    f"[bold]{summary.record_count:,}[/bold]",
                    f"{error_style}{summary.error_count}[/{error_style}]" if error_style else str(summary.error_count),
                    summary.output_path
                )
            
            # Add totals row
            summary_table.add_row(
                "[bold cyan]TOTAL[/bold cyan]",
                "",
                f"[bold green]{total_records:,}[/bold green]",
                f"[bold red]{total_errors}[/bold red]" if total_errors > 0 else "[green]0[/green]",
                "",
                style="bold"
            )
            
            console.print(summary_table)
            console.print()
        except Exception as e:
            console.print(Panel.fit(
                f"[red]❌ Normalization error:[/red] [bold]{e}[/bold]",
                border_style="red",
                box=box.ROUNDED
            ))
        return

    # -------------------------------------------------------------------------
    # ANALYZE
    # -------------------------------------------------------------------------
    if args.command == "analyze":
        from ventra.analysis.commands.report import run_report_command
        
        console.print(Panel.fit(
            "[bold green]🔍 Analyzing Normalized Data[/bold green]",
            border_style="green",
            box=box.ROUNDED
        ))
        console.print()
        
        if args.analyze_cmd == "report":
            run_report_command(args)
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

        # Route based on domain (events or resources)
        if args.collect_domain == "events":
            # Domain A: Events
            console.print(Panel.fit(
                "[bold cyan]📡 Collecting Events (Domain A)[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED
            ))
            console.print(f"[cyan]Case:[/cyan] [bold]{case_name}[/bold] | [cyan]Region:[/cyan] [bold]{args.region}[/bold]")
            console.print()
            
            if args.collect_target == "cloudtrail":
                if args.cloudtrail_cmd == "history":
                    return run_cloudtrail_history(args)

                if args.cloudtrail_cmd == "s3":
                    return run_cloudtrail_s3(args)

                if args.cloudtrail_cmd == "lake":
                    return run_cloudtrail_lake(args)

                if args.cloudtrail_cmd == "all":
                    console.print("[bold cyan]🔄 Running CloudTrail history + s3 collectors...[/bold cyan]")
                    run_cloudtrail_history(args)
                    run_cloudtrail_s3(args)
                    console.print("[green]✓[/green] [bold green]Completed combined collectors[/bold green]")
                    return
            
            # GuardDuty (Events)
            if args.collect_target == "guardduty":
                from ventra.collector.events.guardduty_findings import run_guardduty_findings
                from ventra.collector.events.guardduty_malware import run_guardduty_malware
                
                if args.guardduty_cmd == "findings":
                    return run_guardduty_findings(args)
                if args.guardduty_cmd == "malware":
                    return run_guardduty_malware(args)
            
            # SecurityHub (Events)
            if args.collect_target == "securityhub":
                from ventra.collector.events.securityhub_findings import run_securityhub_findings
                return run_securityhub_findings(args)
            
            # CloudWatch Logs (Events)
            if args.collect_target == "cloudwatch":
                from ventra.collector.events.cloudwatch_log_group import run_cloudwatch_log_group
                return run_cloudwatch_log_group(args)
            
            # VPC Flow Logs (Events)
            if args.collect_target == "vpc":
                from ventra.collector.events.vpc_flow_logs import run_vpc_flow_logs
                
                if args.vpc_cmd == "flowlogs":
                    return run_vpc_flow_logs(args)
            
            # ELB Access Logs (Events)
            if args.collect_target == "elb":
                from ventra.collector.events.elb_access_logs import run_elb_access_logs
                from ventra.collector.events.alb_access_logs import run_alb_access_logs
                from ventra.collector.events.nlb_access_logs import run_nlb_access_logs
                
                if args.elb_cmd == "access-logs":
                    return run_elb_access_logs(args)
                if args.elb_cmd == "alb":
                    return run_alb_access_logs(args)
                if args.elb_cmd == "nlb":
                    return run_nlb_access_logs(args)
            
            # S3 Access Logs (Events)
            if args.collect_target == "s3":
                from ventra.collector.events.s3_access_logs import run_s3_access_logs
                
                if args.s3_cmd == "access":
                    return run_s3_access_logs(args)
            
            # Route53 Resolver Query Logs (Events)
            if args.collect_target == "route53":
                from ventra.collector.events.route53_resolver_query_logs import run_route53_resolver_query_logs
                
                if args.route53_cmd == "query-logs":
                    return run_route53_resolver_query_logs(args)
            
            # WAF Logs (Events)
            if args.collect_target == "waf":
                from ventra.collector.events.waf_logs import run_waf_logs
                return run_waf_logs(args)
            
            # CloudFront Access Logs (Events - Optional)
            if args.collect_target == "cloudfront":
                from ventra.collector.events.cloudfront_access_logs import run_cloudfront_access_logs
                return run_cloudfront_access_logs(args)
            
            # Detective Findings (Events - Optional)
            if args.collect_target == "detective":
                from ventra.collector.events.detective_findings import run_detective_findings
                return run_detective_findings(args)

        elif args.collect_domain == "resources":
            # Domain B: Resources
            console.print(Panel.fit(
                "[bold yellow]📦 Collecting Resources (Domain B)[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED
            ))
            console.print()
            
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
                    from ventra.collector.resources.ec2.ec2_metadata_active import run_ec2_metadata_active
                    return run_ec2_metadata_active(args)
                
                if args.ec2_cmd == "volumes":
                    from ventra.collector.resources.ec2.ec2_volumes import run_ec2_volumes
                    return run_ec2_volumes(args)
                
                if args.ec2_cmd == "snapshots":
                    from ventra.collector.resources.ec2.ec2_snapshots import run_ec2_snapshots
                    return run_ec2_snapshots(args)
                
                if args.ec2_cmd == "all":
                    from ventra.collector.resources.ec2.ec2_all import run_ec2_all
                    return run_ec2_all(args)
            
            # IAM (Resources)
            if args.collect_target == "iam":
                from ventra.collector.resources.iam.iam import run_iam_all
                from ventra.collector.resources.iam.users import run_iam_user
                from ventra.collector.resources.iam.roles import run_iam_role
                from ventra.collector.resources.iam.groups import run_iam_group
                from ventra.collector.resources.iam.policies import run_iam_policy
            
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
        
            # Lambda (Resources)
            if args.collect_target == "lambda":
                import importlib
                lambda_functions = importlib.import_module("ventra.collector.resources.lambda.lambda_functions")
                lambda_config = importlib.import_module("ventra.collector.resources.lambda.lambda_config")
                lambda_env_vars = importlib.import_module("ventra.collector.resources.lambda.lambda_env_vars")
                lambda_policy = importlib.import_module("ventra.collector.resources.lambda.lambda_policy")
                lambda_code = importlib.import_module("ventra.collector.resources.lambda.lambda_code")
                lambda_all = importlib.import_module("ventra.collector.resources.lambda.lambda_all")
                
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
            
            # KMS (Resources)
            if args.collect_target == "kms":
                from ventra.collector.resources.kms.kms import run_kms
                return run_kms(args)
            
            # DynamoDB (Resources)
            if args.collect_target == "dynamodb":
                from ventra.collector.resources.dynamodb.dynamodb_tables import run_dynamodb_tables
                from ventra.collector.resources.dynamodb.dynamodb_backups import run_dynamodb_backups
                from ventra.collector.resources.dynamodb.dynamodb_streams import run_dynamodb_streams
                from ventra.collector.resources.dynamodb.dynamodb_all import run_dynamodb_all
            
                if args.dynamodb_cmd == "tables":
                    return run_dynamodb_tables(args)
                if args.dynamodb_cmd == "backups":
                    return run_dynamodb_backups(args)
                if args.dynamodb_cmd == "streams":
                    return run_dynamodb_streams(args)
                if args.dynamodb_cmd == "all":
                    return run_dynamodb_all(args)
            
            # SNS (Resources)
            if args.collect_target == "sns":
                from ventra.collector.resources.sns.sns_topics import run_sns_topics
                from ventra.collector.resources.sns.sns_subscriptions import run_sns_subscriptions
                from ventra.collector.resources.sns.sns_all import run_sns_all
                
                if args.sns_cmd == "topics":
                    return run_sns_topics(args)
                if args.sns_cmd == "subscriptions":
                    return run_sns_subscriptions(args)
                if args.sns_cmd == "all":
                    return run_sns_all(args)
            
            # SQS (Resources)
            if args.collect_target == "sqs":
                from ventra.collector.resources.sqs.sqs_queues import run_sqs_queues
                from ventra.collector.resources.sqs.sqs_messages import run_sqs_messages
                from ventra.collector.resources.sqs.sqs_all import run_sqs_all
                
                if args.sqs_cmd == "queues":
                    return run_sqs_queues(args)
                if args.sqs_cmd == "messages":
                    return run_sqs_messages(args)
                if args.sqs_cmd == "all":
                    return run_sqs_all(args)
            
            # API Gateway (Resources)
            if args.collect_target == "apigw":
                from ventra.collector.resources.apigw.apigw_rest_apis import run_apigw_rest_apis
                from ventra.collector.resources.apigw.apigw_routes import run_apigw_routes
                from ventra.collector.resources.apigw.apigw_integrations import run_apigw_integrations
                from ventra.collector.resources.apigw.apigw_all import run_apigw_all
                
                if args.apigw_cmd == "rest-apis":
                    return run_apigw_rest_apis(args)
                if args.apigw_cmd == "routes":
                    return run_apigw_routes(args)
                if args.apigw_cmd == "integrations":
                    return run_apigw_integrations(args)
                if args.apigw_cmd == "all":
                    return run_apigw_all(args)
        
            # EKS (Resources)
            if args.collect_target == "eks":
                from ventra.collector.resources.eks.eks_clusters import run_eks_clusters
                from ventra.collector.resources.eks.eks_nodegroups import run_eks_nodegroups
                from ventra.collector.resources.eks.eks_addons import run_eks_addons
                from ventra.collector.resources.eks.eks_security import run_eks_security
                from ventra.collector.resources.eks.eks_networking import run_eks_networking
                from ventra.collector.resources.eks.eks_oidc import run_eks_oidc
                from ventra.collector.resources.eks.eks_logs_config import run_eks_logs_config
                from ventra.collector.resources.eks.eks_fargate import run_eks_fargate
                from ventra.collector.resources.eks.eks_controlplane_logs import run_eks_controlplane_logs
                from ventra.collector.resources.eks.eks_all import run_eks_all
                
                if args.eks_cmd == "clusters":
                    return run_eks_clusters(args)
                if args.eks_cmd == "nodegroups":
                    return run_eks_nodegroups(args)
                if args.eks_cmd == "addons":
                    return run_eks_addons(args)
                if args.eks_cmd == "security":
                    return run_eks_security(args)
                if args.eks_cmd == "networking":
                    return run_eks_networking(args)
                if args.eks_cmd == "oidc":
                    return run_eks_oidc(args)
                if args.eks_cmd == "logs-config":
                    return run_eks_logs_config(args)
                if args.eks_cmd == "fargate":
                    return run_eks_fargate(args)
                if args.eks_cmd == "controlplane-logs":
                    return run_eks_controlplane_logs(args)
                if args.eks_cmd == "all":
                    return run_eks_all(args)
            
            # VPC (Resources - info, subnets, routes, etc.)
            if args.collect_target == "vpc":
                from ventra.collector.resources.vpc.vpc import (
                    collect_vpc_info,
                    collect_vpc_subnets,
                    collect_vpc_routes,
                    collect_vpc_security_groups,
                    collect_vpc_nacls,
                    collect_vpc_endpoints,
                    collect_vpc_internet_gateways,
                    collect_vpc_nat_gateways,
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
                if args.vpc_cmd == "all":
                    return collect_vpc_all(args)
            
            # CloudWatch (Resources - alarms, dashboards)
            if args.collect_target == "cloudwatch":
                from ventra.collector.resources.cloudwatch.cloudwatch_alarms import run_cloudwatch_alarms
                from ventra.collector.resources.cloudwatch.cloudwatch_dashboards import run_cloudwatch_dashboards
                
                if args.cloudwatch_cmd == "alarms":
                    return run_cloudwatch_alarms(args)
                if args.cloudwatch_cmd == "dashboards":
                    return run_cloudwatch_dashboards(args)
            
            # S3 (Resources - buckets, objects, versions)
            if args.collect_target == "s3":
                from ventra.collector.resources.s3.s3_bucket_info import run_s3_bucket_info
                from ventra.collector.resources.s3.s3_objects import run_s3_objects
                from ventra.collector.resources.s3.s3_versions import run_s3_versions
                from ventra.collector.resources.s3.s3_all import run_s3_all
                
                if args.s3_cmd == "bucket-info":
                    return run_s3_bucket_info(args)
                if args.s3_cmd == "objects":
                    return run_s3_objects(args)
                if args.s3_cmd == "versions":
                    return run_s3_versions(args)
                if args.s3_cmd == "all":
                    return run_s3_all(args)
            
            # VPC (Resources - info, subnets, routes, etc.)
            if args.collect_target == "vpc":
                from ventra.collector.resources.vpc.vpc import (
                    collect_vpc_info,
                    collect_vpc_subnets,
                    collect_vpc_routes,
                    collect_vpc_security_groups,
                    collect_vpc_nacls,
                    collect_vpc_endpoints,
                    collect_vpc_internet_gateways,
                    collect_vpc_nat_gateways,
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
                if args.vpc_cmd == "all":
                    return collect_vpc_all(args)
            
            # S3 (Resources - buckets, objects, versions)
            if args.collect_target == "s3":
                from ventra.collector.resources.s3.s3_bucket_info import run_s3_bucket_info
                from ventra.collector.resources.s3.s3_objects import run_s3_objects
                from ventra.collector.resources.s3.s3_versions import run_s3_versions
                from ventra.collector.resources.s3.s3_all import run_s3_all
                
                if args.s3_cmd == "bucket-info":
                    return run_s3_bucket_info(args)
                if args.s3_cmd == "objects":
                    return run_s3_objects(args)
                if args.s3_cmd == "versions":
                    return run_s3_versions(args)
                if args.s3_cmd == "all":
                    return run_s3_all(args)
            
            # ELB (Resources - load balancers, target groups, listeners)
            if args.collect_target == "elb":
                from ventra.collector.resources.elb.elb_all import run_elb_all
                from ventra.collector.resources.elb.elb_listeners import run_elb_listeners
                from ventra.collector.resources.elb.elb_target_groups import run_elb_target_groups
                
                if args.elb_cmd == "all":
                    return run_elb_all(args)
                if args.elb_cmd == "listeners":
                    return run_elb_listeners(args)
                if args.elb_cmd == "target-groups":
                    return run_elb_target_groups(args)
            
            # Route53 (Resources - hosted zones, records)
            if args.collect_target == "route53":
                from ventra.collector.resources.route53.route53_hosted_zones import run_route53_hosted_zones
                from ventra.collector.resources.route53.route53_records import run_route53_records
                from ventra.collector.resources.route53.route53_all import run_route53_all
                
                if args.route53_cmd == "hosted-zones":
                    return run_route53_hosted_zones(args)
                if args.route53_cmd == "records":
                    return run_route53_records(args)
                if args.route53_cmd == "all":
                    return run_route53_all(args)
            
            # CloudWatch (Resources - alarms, dashboards)
            if args.collect_target == "cloudwatch":
                from ventra.collector.resources.cloudwatch.cloudwatch_alarms import run_cloudwatch_alarms
                from ventra.collector.resources.cloudwatch.cloudwatch_dashboards import run_cloudwatch_dashboards
                
                if args.cloudwatch_cmd == "alarms":
                    return run_cloudwatch_alarms(args)
                if args.cloudwatch_cmd == "dashboards":
                    return run_cloudwatch_dashboards(args)
            
            # EventBridge (Resources - rules, buses, targets)
            if args.collect_target == "eventbridge":
                from ventra.collector.resources.eventbridge.eventbridge_rules import run_eventbridge_rules
                from ventra.collector.resources.eventbridge.eventbridge_targets import run_eventbridge_targets
                from ventra.collector.resources.eventbridge.eventbridge_buses import run_eventbridge_buses
                from ventra.collector.resources.eventbridge.eventbridge_all import run_eventbridge_all
                
                if args.eventbridge_cmd == "rules":
                    return run_eventbridge_rules(args)
                if args.eventbridge_cmd == "targets":
                    return run_eventbridge_targets(args)
                if args.eventbridge_cmd == "buses":
                    return run_eventbridge_buses(args)
                if args.eventbridge_cmd == "all":
                    return run_eventbridge_all(args)
            


# =============================================================================
# CLI BUILDER
# =============================================================================
def build_cli():

    parser = argparse.ArgumentParser(
        prog="ventra",
        description="Ventra - Cloud DFIR Collection & Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For more information, visit: https://github.com/yourusername/ventra"
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
    # STATUS
    # =========================================================================
    status = sub.add_parser("status", help="Show collection status")
    status_sub = status.add_subparsers(dest="status_cmd", required=True)
    
    status_collectors = status_sub.add_parser("collectors", help="Show collector status across cases")
    status_collectors.add_argument("--cases", type=str, nargs="+", help="Specific cases to check (default: all cases)")

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
    # ANALYZE
    # =========================================================================
    analyze = sub.add_parser("analyze", help="Analyze normalized data and generate DFIR reports")
    analyze_sub = analyze.add_subparsers(dest="analyze_cmd", required=True)
    
    report = analyze_sub.add_parser("report", help="Generate DFIR investigation report")
    report.add_argument("--case", type=str, required=True, help="Case name")
    report.add_argument("--format", type=str, choices=["text", "json"], default="text", help="Report format (default: text)")
    report.add_argument("--output", type=str, help="Output file path (default: case/reports/dfir_report.{txt|json})")

    # =========================================================================
    # COLLECT
    # =========================================================================
    collect = sub.add_parser("collect", help="Run Ventra collectors")
    collect.add_argument("--profile", type=str, help="Ventra internal profile")
    collect.add_argument("--region", type=str, help="Override region")

    collect_sub = collect.add_subparsers(dest="collect_domain", required=True)
    
    # Domain A: Events (Activity Logs)
    events = collect_sub.add_parser("events", help="Collect activity logs and events (Domain A)")
    events_sub = events.add_subparsers(dest="collect_target", required=True)
    
    # Domain B: Resources (Environment State)  
    resources = collect_sub.add_parser("resources", help="Collect resource metadata and configuration snapshots (Domain B)")
    resources_sub = resources.add_subparsers(dest="collect_target", required=True)

    # =========================================================================
    # DOMAIN A: EVENTS
    # =========================================================================
    
    # CLOUDTRAIL (Events)
    ct = events_sub.add_parser("cloudtrail", help="Collect CloudTrail API activity logs")
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

    # =========================================================================
    # DOMAIN B: RESOURCES
    # =========================================================================
    
    # EC2 (Resources)
    ec2 = resources_sub.add_parser("ec2", help="Collect EC2 instance metadata and configuration")
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

    # VPC (Resources - info, subnets, routes, etc.)
    vpc = resources_sub.add_parser("vpc", help="Collect VPC network infrastructure metadata")
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
    
    # all
    vpc_all = vpc_sub.add_parser("all", help="Run all VPC resource collectors")
    vpc_all.add_argument("--case", type=str, required=True, help="Case name")
    vpc_all.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_all.add_argument("--output", type=str, help="Override output directory")

    # VPC Flow Logs (Events) - separate parser
    vpc_logs = events_sub.add_parser("vpc", help="Collect VPC flow log events")
    vpc_logs_sub = vpc_logs.add_subparsers(dest="vpc_cmd", required=True)
    
    vpc_flowlogs = vpc_logs_sub.add_parser("flowlogs", help="Collect VPC flow log configurations and events")
    vpc_flowlogs.add_argument("--case", type=str, required=True, help="Case name")
    vpc_flowlogs.add_argument("--vpc-id", type=str, help="Filter by specific VPC ID (optional)")
    vpc_flowlogs.add_argument("--hours", type=int, help="Retrieve last N hours of CloudWatch Logs events (optional)")
    vpc_flowlogs.add_argument("--output", type=str, help="Override output directory")

    # IAM (Resources)
    iam = resources_sub.add_parser("iam", help="Collect IAM users, roles, groups, and policies")
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

    # S3 (Resources - buckets, objects, versions)
    s3 = resources_sub.add_parser("s3", help="Collect S3 bucket metadata, objects, and versions")
    s3_sub = s3.add_subparsers(dest="s3_cmd", required=True)
    
    # bucket-info
    s3_bucket_info = s3_sub.add_parser("bucket-info", help="Bucket metadata, ACL, policy, encryption, object-lock, lifecycle, replication, CORS, website config")
    s3_bucket_info.add_argument("--case", type=str, required=True, help="Case name")
    s3_bucket_info.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_bucket_info.add_argument("--output", type=str, help="Override output directory")
    
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
    s3_all = s3_sub.add_parser("all", help="Run all S3 resource collectors for a bucket")
    s3_all.add_argument("--case", type=str, required=True, help="Case name")
    s3_all.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_all.add_argument("--prefix", type=str, help="Prefix for objects/versions collection (optional)")
    s3_all.add_argument("--output", type=str, help="Override output directory")

    # S3 Access Logs (Events) - separate parser
    s3_logs = events_sub.add_parser("s3", help="Collect S3 access logs")
    s3_logs_sub = s3_logs.add_subparsers(dest="s3_cmd", required=True)
    
    s3_access = s3_logs_sub.add_parser("access", help="Access points, access-point policies, cross-account principals, public exposure checks, and access logs")
    s3_access.add_argument("--case", type=str, required=True, help="Case name")
    s3_access.add_argument("--bucket", type=str, required=True, help="S3 bucket name")
    s3_access.add_argument("--output", type=str, help="Override output directory")

    # GuardDuty (Events)
    guardduty = events_sub.add_parser("guardduty", help="Collect GuardDuty security findings and events")
    guardduty_sub = guardduty.add_subparsers(dest="guardduty_cmd", required=True)
    
    # findings
    gd_findings = guardduty_sub.add_parser("findings", help="Collect GuardDuty findings")
    gd_findings.add_argument("--case", type=str, required=True, help="Case name")
    gd_findings.add_argument("--severity", type=str, help="Filter by severity (low, medium, high, critical)")
    gd_findings.add_argument("--resource", type=str, help="Filter by resource ID (e.g., i-1234)")
    gd_findings.add_argument("--output", type=str, help="Override output directory")
    
    # malware
    gd_malware = guardduty_sub.add_parser("malware", help="Collect EBS malware-scan results")
    gd_malware.add_argument("--case", type=str, required=True, help="Case name")
    gd_malware.add_argument("--output", type=str, help="Override output directory")

    # CloudWatch (Resources - alarms, dashboards)
    cloudwatch = resources_sub.add_parser("cloudwatch", help="Collect CloudWatch alarms and dashboards")
    cw_sub = cloudwatch.add_subparsers(dest="cloudwatch_cmd", required=True)
    
    # alarms
    cw_alarms = cw_sub.add_parser("alarms", help="Collect CloudWatch alarms")
    cw_alarms.add_argument("--case", type=str, required=True, help="Case name")
    cw_alarms.add_argument("--output", type=str, help="Override output directory")
    
    # dashboards
    cw_dashboards = cw_sub.add_parser("dashboards", help="Collect CloudWatch dashboards")
    cw_dashboards.add_argument("--case", type=str, required=True, help="Case name")
    cw_dashboards.add_argument("--output", type=str, help="Override output directory")
    
    # CloudWatch Logs (Events) - single parser for log group and events
    cw_logs_events = events_sub.add_parser("cloudwatch", help="Collect CloudWatch log group metadata and log events")
    cw_logs_events.add_argument("--case", type=str, required=True, help="Case name")
    cw_logs_events.add_argument("--group", type=str, required=True, help="Log group name (e.g., '/aws/lambda/my-function')")
    cw_logs_events.add_argument("--hours", type=int, help="Collect log events from last N hours (optional)")
    cw_logs_events.add_argument("--output", type=str, help="Override output directory")

    # KMS (Resources)
    kms = resources_sub.add_parser("kms", help="Collect KMS keys and key policies")
    kms.add_argument("--case", type=str, required=True, help="Case name")
    kms.add_argument("--output", type=str, help="Override output directory")

    # EventBridge (Resources)
    eventbridge = resources_sub.add_parser("eventbridge", help="Collect EventBridge rules, buses, and targets")
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

    # Lambda (Resources)
    lambda_parser = resources_sub.add_parser("lambda", help="Collect Lambda function metadata, config, and code")
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

    # DynamoDB (Resources)
    dynamodb = resources_sub.add_parser("dynamodb", help="Collect DynamoDB tables, backups, and streams")
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

    # SNS (Resources)
    sns = resources_sub.add_parser("sns", help="Collect SNS topics and subscriptions")
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

    # SQS (Resources)
    sqs = resources_sub.add_parser("sqs", help="Collect SQS queues and messages")
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

    # API Gateway (Resources)
    apigw = resources_sub.add_parser("apigw", help="Collect API Gateway REST APIs, routes, and integrations")
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

    # ELB (Resources - load balancers, listeners, target groups)
    elb = resources_sub.add_parser("elb", help="Collect ELB load balancers, listeners, and target groups")
    elb_sub = elb.add_subparsers(dest="elb_cmd", required=True)
    
    elb_listeners = elb_sub.add_parser("listeners", help="Collect load balancer listeners")
    elb_listeners.add_argument("--case", type=str, required=True, help="Case name")
    elb_listeners.add_argument("--output", type=str, help="Override output directory")
    
    elb_target_groups = elb_sub.add_parser("target-groups", help="Collect target groups")
    elb_target_groups.add_argument("--case", type=str, required=True, help="Case name")
    elb_target_groups.add_argument("--output", type=str, help="Override output directory")
    
    elb_all = elb_sub.add_parser("all", help="Collect all ELB resources (listeners, target groups)")
    elb_all.add_argument("--case", type=str, required=True, help="Case name")
    elb_all.add_argument("--output", type=str, help="Override output directory")

    # ELB Access Logs (Events) - separate parser
    elb_logs = events_sub.add_parser("elb", help="Collect ELB access logs")
    elb_logs_sub = elb_logs.add_subparsers(dest="elb_cmd", required=True)
    
    elb_access_logs = elb_logs_sub.add_parser("access-logs", help="Collect Classic ELB access log configurations")
    elb_access_logs.add_argument("--case", type=str, required=True, help="Case name")
    elb_access_logs.add_argument("--output", type=str, help="Override output directory")
    
    alb_access_logs = elb_logs_sub.add_parser("alb", help="Collect ALB access log configurations")
    alb_access_logs.add_argument("--case", type=str, required=True, help="Case name")
    alb_access_logs.add_argument("--output", type=str, help="Override output directory")
    
    nlb_access_logs = elb_logs_sub.add_parser("nlb", help="Collect NLB access log configurations")
    nlb_access_logs.add_argument("--case", type=str, required=True, help="Case name")
    nlb_access_logs.add_argument("--output", type=str, help="Override output directory")

    # Route53 (Resources - hosted zones, records)
    route53 = resources_sub.add_parser("route53", help="Collect Route53 hosted zones and DNS records")
    route53_sub = route53.add_subparsers(dest="route53_cmd", required=True)
    
    r53_hosted_zones = route53_sub.add_parser("hosted-zones", help="Collect hosted zones")
    r53_hosted_zones.add_argument("--case", type=str, required=True, help="Case name")
    r53_hosted_zones.add_argument("--output", type=str, help="Override output directory")
    
    r53_records = route53_sub.add_parser("records", help="Collect DNS records")
    r53_records.add_argument("--case", type=str, required=True, help="Case name")
    r53_records.add_argument("--zone-id", type=str, help="Specific zone ID (optional, collects all if not provided)")
    r53_records.add_argument("--output", type=str, help="Override output directory")
    
    r53_all = route53_sub.add_parser("all", help="Collect all Route53 resources (zones, records)")
    r53_all.add_argument("--case", type=str, required=True, help="Case name")
    r53_all.add_argument("--zone", type=str, required=True, help="Zone ID or domain name")
    r53_all.add_argument("--output", type=str, help="Override output directory")

    # Route53 Resolver Query Logs (Events) - separate parser
    r53_logs = events_sub.add_parser("route53", help="Collect Route53 Resolver query logs")
    r53_logs_sub = r53_logs.add_subparsers(dest="route53_cmd", required=True)
    
    r53_query_logs = r53_logs_sub.add_parser("query-logs", help="Collect Route53 Resolver query logging configurations and events")
    r53_query_logs.add_argument("--case", type=str, required=True, help="Case name")
    r53_query_logs.add_argument("--output", type=str, help="Override output directory")
    
    # WAF Logs (Events)
    waf = events_sub.add_parser("waf", help="Collect WAF log configurations")
    waf.add_argument("--case", type=str, required=True, help="Case name")
    waf.add_argument("--output", type=str, help="Override output directory")
    
    # CloudFront Access Logs (Events - Optional)
    cloudfront = events_sub.add_parser("cloudfront", help="Collect CloudFront access log configurations (optional)")
    cloudfront.add_argument("--case", type=str, required=True, help="Case name")
    cloudfront.add_argument("--output", type=str, help="Override output directory")
    
    # Detective Findings (Events - Optional)
    detective = events_sub.add_parser("detective", help="Collect Amazon Detective findings (optional)")
    detective.add_argument("--case", type=str, required=True, help="Case name")
    detective.add_argument("--output", type=str, help="Override output directory")

    # EKS (Resources)
    eks = resources_sub.add_parser("eks", help="Collect EKS clusters, nodegroups, and configuration")
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

    # Security Hub (Events)
    securityhub = events_sub.add_parser("securityhub", help="Collect Security Hub security findings")
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
    # Print banner only if not showing help
    import sys
    if len(sys.argv) > 1 and sys.argv[1] not in ['-h', '--help']:
        banner_text = """
[bold cyan]=================================================================[/bold cyan]
[bold cyan]|[/bold cyan]                                                                 [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [bold white]██╗   ██╗███████╗███╗   ██╗████████╗██████╗  █████╗[/bold white]  [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [bold white]██║   ██║██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗[/bold white]  [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [bold white]██║   ██║█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║[/bold white]  [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [bold white]╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║[/bold white]  [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [bold white] ╚████╔╝ ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║[/bold white]  [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [bold white]  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝[/bold white]  [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]                                                                 [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [bold yellow]Cloud DFIR Collection & Analysis Framework[/bold yellow]        [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]  [dim]v0.1.0[/dim]                                              [bold cyan]|[/bold cyan]
[bold cyan]|[/bold cyan]                                                                 [bold cyan]|[/bold cyan]
[bold cyan]=================================================================[/bold cyan]
        """
        console.print(banner_text)
        console.print()
    
    parser = build_cli()
    args = parser.parse_args()
    route(args)


if __name__ == "__main__":
    main()