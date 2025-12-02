"""
Route53 Hosted Zones Collector
Collects Route53 hosted zones.
VERY important for DFIR - DNS is used for stealth C2.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_route53_client(region):
    """Route53 client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("route53")


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


def run_route53_hosted_zones(args):
    """Collect Route53 hosted zones."""
    print(f"[+] Route53 Hosted Zones Collector")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "resources")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        route53_client = _get_route53_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Route53 client: {e}")
        return
    
    try:
        hosted_zones_data = {
            "hosted_zones": [],
        }
        
        print("[+] Listing all hosted zones...")
        paginator = route53_client.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                zone_id = zone.get("Id").split("/")[-1]
                zone_name = zone.get("Name")
                
                print(f"[+] Collecting details for zone: {zone_name}")
                
                zone_info = {
                    "Id": zone_id,
                    "Name": zone_name,
                    "CallerReference": zone.get("CallerReference"),
                    "Config": zone.get("Config", {}),
                }
                
                # Get hosted zone details
                try:
                    zone_details = route53_client.get_hosted_zone(Id=zone_id)
                    zone_info["HostedZone"] = {
                        "Id": zone_details.get("HostedZone", {}).get("Id"),
                        "Name": zone_details.get("HostedZone", {}).get("Name"),
                        "CallerReference": zone_details.get("HostedZone", {}).get("CallerReference"),
                        "Config": zone_details.get("HostedZone", {}).get("Config", {}),
                        "ResourceRecordSetCount": zone_details.get("HostedZone", {}).get("ResourceRecordSetCount", 0),
                    }
                    zone_info["DelegationSet"] = zone_details.get("DelegationSet", {})
                    zone_info["VPCs"] = zone_details.get("VPCs", [])
                except ClientError as e:
                    print(f"      ⚠ Error getting zone details: {e}")
                
                hosted_zones_data["hosted_zones"].append(zone_info)
        
        hosted_zones_data["total_zones"] = len(hosted_zones_data["hosted_zones"])
        print(f"    ✓ Found {hosted_zones_data['total_zones']} hosted zone(s)")
        
        # Save single combined file
        filename = "route53_hosted_zones.json"
        filepath = _save_json_file(output_dir, filename, hosted_zones_data)
        if filepath:
            print(f"\n[✓] Saved hosted zones → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

