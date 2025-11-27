"""
AWS Config Drifts Collector
Collects configuration drifts - when actual configuration differs from expected.
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


def run_config_drifts(args):
    """Collect AWS Config drifts."""
    print(f"[+] AWS Config Drifts Collector")
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
        drifts_data = {
            "drifts": [],
        }
        
        print("[+] Listing all configuration drifts...")
        # Note: Config drifts are typically accessed via compliance checks
        # We'll list compliance summaries which show drifts
        
        try:
            # Get compliance summary
            compliance = config_client.get_compliance_summary_by_config_rule()
            drifts_data["compliance_summary"] = compliance.get("ComplianceSummariesByConfigRule", [])
            
            # Also get compliance by resource type
            compliance_by_resource = config_client.get_compliance_summary_by_resource_type()
            drifts_data["compliance_by_resource_type"] = compliance_by_resource.get("ComplianceSummariesByResourceType", [])
            
            print(f"    ✓ Collected compliance summaries")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchConfigurationRecorderException":
                print("    ⚠ AWS Config is not enabled in this region")
                drifts_data["message"] = "AWS Config is not enabled"
            else:
                print(f"    ⚠ Error getting compliance: {e}")
        
        # Save single combined file
        filename = "config_drifts.json"
        filepath = _save_json_file(output_dir, filename, drifts_data)
        if filepath:
            print(f"\n[✓] Saved drifts → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

