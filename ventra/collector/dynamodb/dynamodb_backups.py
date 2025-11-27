"""
DynamoDB Backups Collector
Collects DynamoDB backup information.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_dynamodb_client(region):
    """DynamoDB client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("dynamodb")


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


def run_dynamodb_backups(args):
    """Collect DynamoDB backups."""
    print(f"[+] DynamoDB Backups Collector")
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
        dynamodb_client = _get_dynamodb_client(args.region)
    except Exception as e:
        print(f"❌ Error getting DynamoDB client: {e}")
        return
    
    try:
        backups_data = {
            "backups": [],
        }
        
        print("[+] Listing all DynamoDB backups...")
        paginator = dynamodb_client.get_paginator("list_backups")
        for page in paginator.paginate():
            for backup in page.get("BackupSummaries", []):
                backup_arn = backup.get("BackupArn")
                
                backup_info = {
                    "TableName": backup.get("TableName"),
                    "TableArn": backup.get("TableArn"),
                    "BackupArn": backup_arn,
                    "BackupName": backup.get("BackupName"),
                    "BackupStatus": backup.get("BackupStatus"),
                    "BackupType": backup.get("BackupType"),
                    "BackupCreationDateTime": str(backup.get("BackupCreationDateTime", "")),
                    "BackupExpiryDateTime": str(backup.get("BackupExpiryDateTime", "")) if backup.get("BackupExpiryDateTime") else None,
                    "BackupSizeBytes": backup.get("BackupSizeBytes", 0),
                }
                
                # Get detailed backup information
                try:
                    backup_details = dynamodb_client.describe_backup(BackupArn=backup_arn)
                    backup_desc = backup_details.get("BackupDescription", {})
                    backup_info["BackupDetails"] = {
                        "BackupArn": backup_desc.get("BackupArn"),
                        "BackupName": backup_desc.get("BackupName"),
                        "BackupStatus": backup_desc.get("BackupStatus"),
                        "BackupType": backup_desc.get("BackupType"),
                        "BackupCreationDateTime": str(backup_desc.get("BackupCreationDateTime", "")),
                        "BackupExpiryDateTime": str(backup_desc.get("BackupExpiryDateTime", "")) if backup_desc.get("BackupExpiryDateTime") else None,
                        "BackupSizeBytes": backup_desc.get("BackupSizeBytes", 0),
                        "SourceTableDetails": backup_desc.get("SourceTableDetails", {}),
                        "SourceTableFeatureDetails": backup_desc.get("SourceTableFeatureDetails", {}),
                    }
                except ClientError as e:
                    print(f"      ⚠ Error getting backup details: {e}")
                
                backups_data["backups"].append(backup_info)
        
        backups_data["total_backups"] = len(backups_data["backups"])
        print(f"    ✓ Found {backups_data['total_backups']} backup(s)")
        
        # Save single combined file
        filename = "dynamodb_backups.json"
        filepath = _save_json_file(output_dir, filename, backups_data)
        if filepath:
            print(f"\n[✓] Saved backups → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

