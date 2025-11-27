"""
GuardDuty Detectors Collector
Collects all GuardDuty detectors across all regions.
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


def run_guradduty_detectors(args):
    """Collect GuardDuty detectors."""
    all_regions = getattr(args, "all_regions", False)
    print(f"[+] GuardDuty Detectors Collector")
    print(f"    All Regions: {all_regions}")
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
        detectors_data = {}
        
        if all_regions:
            # Get all regions
            ec2_client = boto3.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2_client.describe_regions()["Regions"]]
            print(f"[+] Collecting detectors from {len(regions)} regions...\n")
        else:
            regions = [args.region]
        
        for region in regions:
            print(f"[+] Processing region: {region}")
            try:
                gd_client = _get_guardduty_client(region)
                
                # List detectors
                response = gd_client.list_detectors()
                detector_ids = response.get("DetectorIds", [])
                
                if not detector_ids:
                    print(f"    ⚠ No detectors found in {region}")
                    detectors_data[region] = []
                    continue
                
                print(f"    ✓ Found {len(detector_ids)} detector(s)")
                
                region_detectors = []
                for detector_id in detector_ids:
                    try:
                        # Get detector details
                        detector = gd_client.get_detector(DetectorId=detector_id)
                        detector_info = {
                            "DetectorId": detector_id,
                            "CreatedAt": str(detector.get("CreatedAt", "")),
                            "ServiceRole": detector.get("ServiceRole"),
                            "Status": detector.get("Status"),
                            "UpdatedAt": str(detector.get("UpdatedAt", "")),
                            "FindingPublishingFrequency": detector.get("FindingPublishingFrequency"),
                            "Tags": detector.get("Tags", {}),
                        }
                        
                        # Get data sources
                        try:
                            data_sources = gd_client.get_detector(DetectorId=detector_id)
                            detector_info["DataSources"] = data_sources.get("DataSources", {})
                        except Exception:
                            pass
                        
                        region_detectors.append(detector_info)
                    except ClientError as e:
                        print(f"      ⚠ Error getting detector {detector_id}: {e}")
                
                detectors_data[region] = region_detectors
                
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "BadRequestException":
                    # GuardDuty not available in this region
                    print(f"    ⚠ GuardDuty not available in {region}")
                    detectors_data[region] = []
                else:
                    print(f"    ⚠ Error in {region}: {e}")
                    detectors_data[region] = []
        
        # Save single combined file
        filename = "guradduty_detectors.json"
        filepath = _save_json_file(output_dir, filename, detectors_data)
        if filepath:
            print(f"\n[✓] Saved detectors → {filepath}\n")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

