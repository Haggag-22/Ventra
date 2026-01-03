"""
Collector status checker - shows which collectors have data for each case.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from rich.table import Table
from rich import box
from ventra.case.store import list_cases, get_output_base_dir


# Map collector script names to their file patterns
LOGS_COLLECTORS = {
    "cloudtrail_history": ["cloudtrail_history_raw.json"],
    "cloudtrail_s3": ["cloudtrail_s3_*.json"],
    "cloudtrail_lake": ["cloudtrail_lake_*.json"],
    "cloudwatch_log_group": ["cloudwatch_log_group_*.json"],
    "guardduty_findings": ["guardduty_findings.json"],
    "guardduty_malware": ["guardduty_malware.json"],
    "securityhub_findings": ["securityhub_findings.json"],
    "detective_findings": ["detective_findings.json"],
    "s3_access_logs": ["s3_access_logs*.json"],
    "alb_access_logs": ["alb_access_logs*.json"],
    "elb_access_logs": ["elb_access_logs*.json"],
    "nlb_access_logs": ["nlb_access_logs*.json"],
    "cloudfront_access_logs": ["cloudfront_access_logs.json"],
    "waf_logs": ["waf_logs.json"],
    "vpc_flow_logs": ["vpc_flow_logs*.json"],
    "route53_resolver_query_logs": ["route53_resolver_query_logs.json"],
}

RESOURCES_COLLECTORS = {
    "ec2_instances": ["ec2_instances*.json"],
    "ec2_volumes": ["ec2_volumes*.json"],
    "ec2_snapshots": ["ec2_snapshots*.json"],
    "ec2_security_groups": ["ec2_security_groups*.json"],
    "ec2_network_interfaces": ["ec2_network_interfaces*.json"],
    "ec2_metadata_active": ["ec2_metadata_active*.json"],
    "ec2_metadata_passive": ["ec2_metadata_passive*.json"],
    "iam_users": ["iam_users*.json"],
    "iam_roles": ["iam_roles*.json"],
    "iam_policies": ["iam_policies*.json"],
    "iam_groups": ["iam_groups*.json"],
    "s3_buckets": ["s3_buckets*.json"],
    "s3_objects": ["s3_objects*.json"],
    "s3_versions": ["s3_versions*.json"],
    "s3_bucket_policies": ["s3_bucket_policies*.json"],
    "lambda_functions": ["lambda_functions*.json"],
    "lambda_config": ["lambda_config*.json"],
    "lambda_env_vars": ["lambda_env_vars*.json"],
    "lambda_policy": ["lambda_policy*.json"],
    "lambda_code": ["lambda_code*.json"],
    "dynamodb_tables": ["dynamodb_tables*.json"],
    "dynamodb_backups": ["dynamodb_backups*.json"],
    "apigw_rest_apis": ["apigw_rest_apis*.json"],
    "apigw_integrations": ["apigw_integrations*.json"],
    "apigw_routes": ["apigw_routes*.json"],
    "eks_clusters": ["eks_clusters*.json"],
    "eks_nodegroups": ["eks_nodegroups*.json"],
    "eks_security": ["eks_security*.json"],
    "eventbridge_rules": ["eventbridge_rules*.json"],
    "eventbridge_targets": ["eventbridge_targets*.json"],
    "kms_keys": ["kms_keys*.json"],
    "vpc": ["vpc*.json"],
    "vpc_subnets": ["vpc_subnets*.json"],
    "vpc_route_tables": ["vpc_route_tables*.json"],
    "vpc_security_groups": ["vpc_security_groups*.json"],
    "vpc_network_acls": ["vpc_network_acls*.json"],
    "route53_hosted_zones": ["route53_hosted_zones*.json"],
    "route53_records": ["route53_records*.json"],
}


def _match_pattern(filename: str, pattern: str) -> bool:
    """Check if filename matches a pattern (supports * wildcard)."""
    # Convert glob pattern to regex
    regex_pattern = pattern.replace("*", ".*")
    return bool(re.match(regex_pattern, filename))


def _check_collector_in_case(case_dir: Path, collector_name: str, patterns: List[str], subdir: str) -> Tuple[bool, Optional[str]]:
    """Check if a collector has data in a case directory."""
    if not os.path.exists(case_dir):
        return False, None
    
    # Check in the specified subdirectory
    search_dir = case_dir / subdir
    
    if not search_dir.exists():
        return False, None
    
    # Check all JSON files in subdirectory (recursive, because some collectors
    # store outputs under nested folders like resources/iam/*.json)
    for json_file in search_dir.rglob("*.json"):
        filename = json_file.name
        
        # Skip normalized files
        if "normalized" in str(json_file):
            continue
        
        # Check if filename matches any pattern
        for pattern in patterns:
            if _match_pattern(filename, pattern):
                # Return relative path from case directory
                rel_path = os.path.relpath(json_file, case_dir)
                return True, rel_path
    
    return False, None


def _apply_all_markers(
    case_dir: Path,
    resources_status: Dict[str, Dict[str, Tuple[bool, Optional[str]]]],
    case_key: str,
) -> None:
    """
    If a service-level 'all' collector ran, mark its related per-service resource
    collectors as collected in status.
    """
    resources_dir = case_dir / "resources"
    if not resources_dir.exists():
        return

    def _mark(collectors: List[str], rel_path: str) -> None:
        for c in collectors:
            if c in resources_status:
                resources_status[c][case_key] = (True, rel_path)

    # EC2 all → mark all EC2-related collectors
    ec2_all = resources_dir / "ec2_all.json"
    if ec2_all.exists():
        _mark(
            [
                "ec2_instances",
                "ec2_volumes",
                "ec2_snapshots",
                "ec2_security_groups",
                "ec2_network_interfaces",
                "ec2_metadata_active",
                "ec2_metadata_passive",
            ],
            os.path.relpath(ec2_all, case_dir),
        )

    # VPC all → mark all VPC-related collectors
    vpc_all = resources_dir / "vpc_all.json"
    if vpc_all.exists():
        _mark(
            [
                "vpc",
                "vpc_subnets",
                "vpc_route_tables",
                "vpc_security_groups",
                "vpc_network_acls",
            ],
            os.path.relpath(vpc_all, case_dir),
        )

    # IAM all → mark all IAM-related collectors (saved under resources/iam/)
    iam_all = resources_dir / "iam" / "iam_all.json"
    if iam_all.exists():
        _mark(
            [
                "iam_users",
                "iam_roles",
                "iam_policies",
                "iam_groups",
            ],
            os.path.relpath(iam_all, case_dir),
        )


def check_collector_status(case_names: Optional[List[str]] = None) -> Tuple[Dict[str, Dict[str, Tuple[bool, Optional[str]]]], Dict[str, Dict[str, Tuple[bool, Optional[str]]]]]:
    """
    Check collector status across cases, separated by logs and resources.
    
    Args:
        case_names: Optional list of case names to check. If None, checks all cases.
    
    Returns:
        Tuple of (logs_status, resources_status)
        Each is a dict mapping collector -> case -> (is_collected, file_path)
    """
    # Get all cases
    if case_names:
        cases = []
        for name in case_names:
            from ventra.case.store import get_case_dir
            case_dir = get_case_dir(name)
            if case_dir:
                cases.append({
                    'name': os.path.basename(case_dir),
                    'dir_name': os.path.basename(case_dir),
                    'path': case_dir
                })
    else:
        cases = list_cases()
    
    # Build status dicts for logs and resources
    logs_status = {}
    resources_status = {}
    
    for collector_name, patterns in LOGS_COLLECTORS.items():
        logs_status[collector_name] = {}
        for case in cases:
            case_dir = Path(case['path'])
            is_collected, file_path = _check_collector_in_case(case_dir, collector_name, patterns, "logs")
            logs_status[collector_name][case['dir_name']] = (is_collected, file_path)
    
    for collector_name, patterns in RESOURCES_COLLECTORS.items():
        resources_status[collector_name] = {}
        for case in cases:
            case_dir = Path(case['path'])
            is_collected, file_path = _check_collector_in_case(case_dir, collector_name, patterns, "resources")
            resources_status[collector_name][case['dir_name']] = (is_collected, file_path)

    # Apply "all" markers after initial scan so per-resource rows can reflect
    # service-level all collectors (ec2 all, vpc all, iam all, ...).
    for case in cases:
        case_dir = Path(case["path"])
        _apply_all_markers(case_dir, resources_status, case["dir_name"])
    
    return logs_status, resources_status


def format_status_tables(
    logs_status: Dict[str, Dict[str, Tuple[bool, Optional[str]]]], 
    resources_status: Dict[str, Dict[str, Tuple[bool, Optional[str]]]], 
    case_names: Optional[List[str]] = None
) -> Tuple[Table, Table]:
    """
    Format collector status as two Rich tables (one for logs, one for resources).
    
    Returns:
        Tuple of (logs_table, resources_table)
    """
    # Get all cases from both status dicts
    all_cases = set()
    for collector_status in logs_status.values():
        all_cases.update(collector_status.keys())
    for collector_status in resources_status.values():
        all_cases.update(collector_status.keys())
    
    if case_names:
        # Normalize case names for comparison (convert to lowercase directory names)
        from ventra.case.store import get_case_dir
        normalized_case_names = set()
        for name in case_names:
            case_dir = get_case_dir(name)
            if case_dir:
                normalized_case_names.add(os.path.basename(case_dir))
        # Filter cases using normalized names
        all_cases = [c for c in sorted(all_cases) if c in normalized_case_names]
    else:
        all_cases = sorted(all_cases)
    
    if not all_cases:
        empty_table = Table(title="[bold yellow]No cases found[/bold yellow]", box=box.ROUNDED)
        return empty_table, empty_table
    
    # Create Logs table
    logs_table = Table(
        title="[bold cyan]📋 Logs Collectors[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        border_style="cyan",
        show_lines=True,
        header_style="bold cyan"
    )
    logs_table.add_column("[bold cyan]Collector Script[/bold cyan]", style="cyan", no_wrap=True, width=30)
    
    # Add case columns
    for case in all_cases:
        logs_table.add_column(f"[bold yellow]{case}[/bold yellow]", justify="center", width=15)
    
    # Add rows for logs collectors
    for collector in sorted(logs_status.keys()):
        row = [f"[cyan]{collector}[/cyan]"]
        for case in all_cases:
            is_collected, file_path = logs_status[collector].get(case, (False, None))
            if is_collected:
                row.append("[bold green]✓ COLLECTED[/bold green]")
            else:
                row.append("[bold red]✗ MISSING[/bold red]")
        logs_table.add_row(*row)
    
    # Create Resources table
    resources_table = Table(
        title="[bold magenta]📦 Resources Collectors[/bold magenta]",
        box=box.ROUNDED,
        show_header=True,
        border_style="magenta",
        show_lines=True,
        header_style="bold magenta"
    )
    resources_table.add_column("[bold magenta]Collector Script[/bold magenta]", style="magenta", no_wrap=True, width=30)
    
    # Add case columns
    for case in all_cases:
        resources_table.add_column(f"[bold yellow]{case}[/bold yellow]", justify="center", width=15)
    
    # Add rows for resources collectors
    for collector in sorted(resources_status.keys()):
        row = [f"[magenta]{collector}[/magenta]"]
        for case in all_cases:
            is_collected, file_path = resources_status[collector].get(case, (False, None))
            if is_collected:
                row.append("[bold green]✓ COLLECTED[/bold green]")
            else:
                row.append("[bold red]✗ MISSING[/bold red]")
        resources_table.add_row(*row)
    
    return logs_table, resources_table


# Legacy function for backwards compatibility
def get_all_collectors() -> List[str]:
    """Get list of all available collectors (legacy - use LOGS_COLLECTORS and RESOURCES_COLLECTORS instead)."""
    all_collectors = set(LOGS_COLLECTORS.keys())
    all_collectors.update(RESOURCES_COLLECTORS.keys())
    return sorted(all_collectors)



