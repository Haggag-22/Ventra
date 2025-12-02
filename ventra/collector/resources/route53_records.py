"""
Route53 Records Collector
Collects DNS records from hosted zones.
Attackers often store: TXT records with commands, C2 domains, data exfiltration entries.
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


def run_route53_records(args):
    """Collect Route53 DNS records."""
    zone_id = getattr(args, "zone_id", None)
    
    print(f"[+] Route53 Records Collector")
    if zone_id:
        print(f"    Zone ID:     {zone_id}")
    else:
        print(f"    All Zones:   Yes")
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
        records_data = {
            "zones_with_records": [],
        }
        
        # Get hosted zone IDs
        if zone_id:
            zone_ids = [zone_id]
        else:
            print("[+] Listing all hosted zones...")
            paginator = route53_client.get_paginator("list_hosted_zones")
            zone_ids = []
            for page in paginator.paginate():
                for zone in page.get("HostedZones", []):
                    zone_id_full = zone.get("Id")
                    zone_ids.append(zone_id_full.split("/")[-1])
            print(f"    ✓ Found {len(zone_ids)} hosted zone(s)")
        
        # Get records for each zone
        for zone_id_item in zone_ids:
            print(f"[+] Collecting records for zone: {zone_id_item}")
            
            try:
                zone_records_info = {
                    "ZoneId": zone_id_item,
                    "Records": [],
                }
                
                # List resource record sets
                paginator = route53_client.get_paginator("list_resource_record_sets")
                for page in paginator.paginate(HostedZoneId=zone_id_item):
                    for record in page.get("ResourceRecordSets", []):
                        record_info = {
                            "Name": record.get("Name"),
                            "Type": record.get("Type"),
                            "TTL": record.get("TTL"),
                            "ResourceRecords": record.get("ResourceRecords", []),
                            "AliasTarget": record.get("AliasTarget", {}),
                            "SetIdentifier": record.get("SetIdentifier"),
                            "Weight": record.get("Weight"),
                            "Region": record.get("Region"),
                            "GeoLocation": record.get("GeoLocation", {}),
                            "Failover": record.get("Failover"),
                            "MultiValueAnswer": record.get("MultiValueAnswer"),
                            "TrafficPolicyInstanceId": record.get("TrafficPolicyInstanceId"),
                        }
                        zone_records_info["Records"].append(record_info)
                
                records_data["zones_with_records"].append(zone_records_info)
                
                # Count suspicious record types
                txt_count = sum(1 for r in zone_records_info["Records"] if r["Type"] == "TXT")
                cname_count = sum(1 for r in zone_records_info["Records"] if r["Type"] == "CNAME")
                
                print(f"    ✓ Collected {len(zone_records_info['Records'])} record(s)")
                if txt_count > 0:
                    print(f"      ⚠ Found {txt_count} TXT record(s) - potential command storage")
                if cname_count > 0:
                    print(f"      ⚠ Found {cname_count} CNAME record(s) - potential C2 domains")
                
            except ClientError as e:
                print(f"      ⚠ Error getting records: {e}")
        
        records_data["total_zones"] = len(records_data["zones_with_records"])
        total_records = sum(len(z["Records"]) for z in records_data["zones_with_records"])
        records_data["total_records"] = total_records
        
        # Save single combined file
        filename = "route53_records.json"
        if zone_id:
            filename = f"route53_records_{zone_id}.json"
        
        filepath = _save_json_file(output_dir, filename, records_data)
        if filepath:
            print(f"\n[✓] Saved records → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

