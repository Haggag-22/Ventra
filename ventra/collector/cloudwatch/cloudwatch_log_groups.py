"""
CloudWatch Log Groups Collector
Collects all CloudWatch log groups and their metadata.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_cloudwatch_logs_client(region):
    """CloudWatch Logs client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("logs")


def _save_json_file(output_dir, filename, data):
    """Save data to JSON file with pretty printing."""
    filepath = os.path.join(output_dir, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath
    except Exception as e:
        print(f"    ❌ Error saving {filename}: {e}")
        return None


def run_cloudwatch_log_groups(args):
    """Collect all CloudWatch log groups."""
    print(f"[+] CloudWatch Log Groups Collector")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch Logs client: {e}")
        return
    
    try:
        log_groups_data = {
            "log_groups": [],
        }
        
        print("[+] Listing all log groups...")
        paginator = logs_client.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for log_group in page.get("logGroups", []):
                log_group_info = {
                    "logGroupName": log_group.get("logGroupName"),
                    "creationTime": log_group.get("creationTime"),
                    "retentionInDays": log_group.get("retentionInDays"),
                    "metricFilterCount": log_group.get("metricFilterCount", 0),
                    "arn": log_group.get("arn"),
                    "storedBytes": log_group.get("storedBytes", 0),
                    "kmsKeyId": log_group.get("kmsKeyId"),
                }
                log_groups_data["log_groups"].append(log_group_info)
        
        log_groups_data["total_log_groups"] = len(log_groups_data["log_groups"])
        print(f"    ✓ Found {log_groups_data['total_log_groups']} log group(s)")
        
        # Save single combined file
        filename = "cloudwatch_log_groups.json"
        filepath = _save_json_file(output_dir, filename, log_groups_data)
        if filepath:
            print(f"\n[✓] Saved log groups → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

