"""
GuardDuty Details Collector
Collects detailed information for a specific finding.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_guardduty_client(region):
    """GuardDuty client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("guardduty")


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


def run_guradduty_details(args):
    """Collect detailed GuardDuty finding information."""
    finding_id = args.id
    print(f"[+] GuardDuty Details Collector")
    print(f"    Finding ID:  {finding_id}")
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
        gd_client = _get_guardduty_client(args.region)
    except Exception as e:
        print(f"❌ Error getting GuardDuty client: {e}")
        return
    
    try:
        # List detectors first
        print("[+] Finding detectors...")
        response = gd_client.list_detectors()
        detector_ids = response.get("DetectorIds", [])
        
        if not detector_ids:
            print("    ❌ No detectors found in this region")
            return
        
        print(f"    ✓ Found {len(detector_ids)} detector(s)")
        
        finding_details = None
        
        # Try to get finding from each detector
        for detector_id in detector_ids:
            try:
                finding_response = gd_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=[finding_id]
                )
                findings = finding_response.get("Findings", [])
                if findings:
                    finding_details = findings[0]
                    print(f"    ✓ Found finding in detector: {detector_id}")
                    break
            except ClientError as e:
                continue
        
        if not finding_details:
            print(f"    ❌ Finding {finding_id} not found in any detector")
            return
        
        # Save single combined file
        safe_id = finding_id.replace(":", "_").replace("/", "_")
        filename = f"guradduty_details_{safe_id}.json"
        filepath = _save_json_file(output_dir, filename, finding_details)
        if filepath:
            print(f"\n[✓] Saved finding details → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

