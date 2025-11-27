"""
AWS Config Snapshots Collector
Collects configuration snapshots.
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


def run_config_snapshots(args):
    """Collect AWS Config snapshots."""
    print(f"[+] AWS Config Snapshots Collector")
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
        config_client = _get_config_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Config client: {e}")
        return
    
    try:
        snapshots_data = {
            "snapshots": [],
        }
        
        print("[+] Listing all configuration snapshots...")
        paginator = config_client.get_paginator("describe_configuration_snapshots")
        for page in paginator.paginate():
            for snapshot in page.get("ConfigurationSnapshots", []):
                snapshot_info = {
                    "SnapshotId": snapshot.get("SnapshotId"),
                    "ConfigurationSnapshotStatus": snapshot.get("ConfigurationSnapshotStatus"),
                    "StartTime": str(snapshot.get("StartTime", "")),
                    "CompletionTime": str(snapshot.get("CompletionTime", "")) if snapshot.get("CompletionTime") else None,
                    "SnapshotType": snapshot.get("SnapshotType"),
                }
                snapshots_data["snapshots"].append(snapshot_info)
        
        snapshots_data["total_snapshots"] = len(snapshots_data["snapshots"])
        print(f"    ✓ Found {snapshots_data['total_snapshots']} snapshot(s)")
        
        # Save single combined file
        filename = "config_snapshots.json"
        filepath = _save_json_file(output_dir, filename, snapshots_data)
        if filepath:
            print(f"\n[✓] Saved snapshots → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

