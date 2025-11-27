"""
AWS Config History Collector
Collects configuration history for resources.
Config records every resource change: IAM modifications, SG changes, EC2 state changes, S3 bucket policy changes.
This replaces traditional Windows "Registry Timeline" but for cloud.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_config_client(region):
    """AWS Config client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("config")


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


def run_config_history(args):
    """Collect AWS Config history."""
    resource_type = getattr(args, "resource_type", None)
    resource_id = getattr(args, "resource_id", None)
    hours = getattr(args, "hours", 24)
    
    print(f"[+] AWS Config History Collector")
    if resource_type:
        print(f"    Resource Type: {resource_type}")
    if resource_id:
        print(f"    Resource ID:   {resource_id}")
    print(f"    Hours:        {hours}")
    print(f"    Region:       {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:       {output_dir}\n")
    
    try:
        config_client = _get_config_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Config client: {e}")
        return
    
    try:
        history_data = {
            "configuration_history": [],
        }
        
        # Check if Config is enabled
        print("[+] Checking Config status...")
        try:
            recorders = config_client.describe_configuration_recorders()
            if not recorders.get("ConfigurationRecorders"):
                print("    ⚠ AWS Config is not enabled in this region")
                history_data["message"] = "AWS Config is not enabled"
                filename = "config_history.json"
                filepath = _save_json_file(output_dir, filename, history_data)
                if filepath:
                    print(f"\n[✓] Saved status → {filepath}\n")
                return
            print("    ✓ AWS Config is enabled")
        except ClientError as e:
            print(f"    ⚠ Error checking Config status: {e}")
            return
        
        # Get configuration history
        print(f"[+] Collecting configuration history (last {hours} hours)...")
        from datetime import datetime, timedelta, timezone
        
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
        kwargs = {
            "laterTime": end_time,
            "earlierTime": start_time,
        }
        
        if resource_type:
            kwargs["resourceType"] = resource_type
        if resource_id:
            kwargs["resourceId"] = resource_id
        
        paginator = config_client.get_paginator("get_resource_config_history")
        for page in paginator.paginate(**kwargs):
            for item in page.get("configurationItemsList", []):
                history_data["configuration_history"].append({
                    "version": item.get("version"),
                    "accountId": item.get("accountId"),
                    "configurationItemCaptureTime": str(item.get("configurationItemCaptureTime", "")),
                    "configurationItemStatus": item.get("configurationItemStatus"),
                    "configurationStateId": item.get("configurationStateId"),
                    "resourceType": item.get("resourceType"),
                    "resourceId": item.get("resourceId"),
                    "resourceName": item.get("resourceName"),
                    "ARN": item.get("ARN"),
                    "awsRegion": item.get("awsRegion"),
                    "availabilityZone": item.get("availabilityZone"),
                    "configurationItemMD5Hash": item.get("configurationItemMD5Hash"),
                    "configuration": item.get("configuration"),
                    "supplementaryConfiguration": item.get("supplementaryConfiguration", {}),
                    "tags": item.get("tags", {}),
                    "relationships": item.get("relationships", []),
                })
        
        history_data["total_items"] = len(history_data["configuration_history"])
        print(f"    ✓ Collected {history_data['total_items']} configuration history item(s)")
        
        # Save single combined file
        filename = "config_history.json"
        if resource_type:
            safe_type = resource_type.replace("::", "_").replace(":", "_")
            filename = f"config_history_{safe_type}.json"
        
        filepath = _save_json_file(output_dir, filename, history_data)
        if filepath:
            print(f"\n[✓] Saved configuration history → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

