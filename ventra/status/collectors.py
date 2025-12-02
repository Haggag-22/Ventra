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


# Map collector names to their file patterns
COLLECTOR_PATTERNS = {
    "cloudtrail": [
        "cloudtrail_history_raw.json",
        "cloudtrail_s3_*.json",
        "cloudtrail_lake_*.json",
    ],
    "ec2": [
        "ec2_*_all.json",
        "ec2_*_metadata*.json",
        "ec2_*_snapshots.json",
        "ec2_*_volumes.json",
    ],
    "s3": [
        "s3_*_all.json",
        "s3_*.json",  # Also match individual bucket files
    ],
    "iam": [
        "iam_all.json",
        "iam_*.json",
    ],
    "dynamodb": [
        "dynamodb_*_all.json",
        "dynamodb_*.json",
    ],
    "lambda": [
        "lambda_*_all.json",
        "lambda_*.json",
    ],
    "eks": [
        "eks_*_all.json",
        "eks_*.json",
    ],
    "vpc": [
        "vpc_*.json",
    ],
    "elb": [
        "elb_*_all.json",
        "elb_*.json",
    ],
    "eventbridge": [
        "eventbridge_*_all.json",
        "eventbridge_*.json",
    ],
    "guradduty": [
        "guradduty_*_all.json",
        "guradduty_*.json",
        "guradduty_findings.json",
    ],
    "securityhub": [
        "securityhub_findings.json",
        "securityhub_*.json",
    ],
    "kms": [
        "kms_*.json",
    ],
    "sns": [
        "sns_*_all.json",
        "sns_*.json",
    ],
    "sqs": [
        "sqs_*_all.json",
        "sqs_*.json",
    ],
    "apigw": [
        "apigw_*_all.json",
        "apigw_*.json",
    ],
    "cloudwatch": [
        "cloudwatch_*_all.json",
        "cloudwatch_*.json",
    ],
    "route53": [
        "route53_*_all.json",
        "route53_*.json",
    ],
}


def get_all_collectors() -> List[str]:
    """Get list of all available collectors."""
    return sorted(COLLECTOR_PATTERNS.keys())


def _match_pattern(filename: str, pattern: str) -> bool:
    """Check if filename matches a pattern (supports * wildcard)."""
    # Convert glob pattern to regex
    regex_pattern = pattern.replace("*", ".*")
    return bool(re.match(regex_pattern, filename))


def _check_collector_in_case(case_dir: Path, collector: str) -> Tuple[bool, Optional[str]]:
    """Check if a collector has data in a case directory."""
    patterns = COLLECTOR_PATTERNS.get(collector, [])
    
    if not os.path.exists(case_dir):
        return False, None
    
    # Check all JSON files in case directory
    for json_file in case_dir.glob("*.json"):
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


def check_collector_status(case_names: Optional[List[str]] = None) -> Dict[str, Dict[str, Tuple[bool, Optional[str]]]]:
    """
    Check collector status across cases.
    
    Args:
        case_names: Optional list of case names to check. If None, checks all cases.
    
    Returns:
        Dict mapping collector -> case -> (is_collected, file_path)
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
    
    collectors = get_all_collectors()
    
    # Build status dict
    status = {}
    for collector in collectors:
        status[collector] = {}
        for case in cases:
            case_dir = Path(case['path'])
            is_collected, file_path = _check_collector_in_case(case_dir, collector)
            status[collector][case['dir_name']] = (is_collected, file_path)
    
    return status


def format_status_table(status: Dict[str, Dict[str, Tuple[bool, Optional[str]]]], case_names: Optional[List[str]] = None) -> Table:
    """
    Format collector status as a Rich table.
    
    Returns:
        Rich Table object
    """
    if not status:
        table = Table(title="[bold red]No collectors or cases found[/bold red]", box=box.ROUNDED)
        return table
    
    # Get all cases from status
    all_cases = set()
    for collector_status in status.values():
        all_cases.update(collector_status.keys())
    
    if case_names:
        # Filter cases
        all_cases = [c for c in sorted(all_cases) if c in case_names]
    else:
        all_cases = sorted(all_cases)
    
    if not all_cases:
        table = Table(title="[bold yellow]No cases found[/bold yellow]", box=box.ROUNDED)
        return table
    
    collectors = sorted(status.keys())
    
    # Create Rich table with enhanced styling
    table = Table(
        title="[bold magenta]📊 Collector Status[/bold magenta]",
        box=box.ROUNDED,
        show_header=True,
        border_style="magenta",
        show_lines=True,
        header_style="bold magenta"
    )
    table.add_column("[bold cyan]AWS Service[/bold cyan]", style="cyan", no_wrap=True, width=20)
    
    # Add case columns
    for case in all_cases:
        table.add_column(f"[bold yellow]{case}[/bold yellow]", justify="center", width=15)
    
    # Add rows with emoji indicators
    for collector in collectors:
        row = [f"[cyan]{collector}[/cyan]"]
        for case in all_cases:
            is_collected, file_path = status[collector].get(case, (False, None))
            if is_collected:
                row.append("[bold green]✓ COLLECTED[/bold green]")
            else:
                row.append("[bold red]✗ MISSING[/bold red]")
        table.add_row(*row)
    
    return table

