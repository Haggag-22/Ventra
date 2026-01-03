"""
Route53 All Collector
Collects all Route53 information for a hosted zone (zone info, records, query logs) into a single combined file.
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


def _resolve_zone_id(route53_client, zone_identifier):
    """Resolve zone identifier (ID or domain name) to zone ID."""
    # If it looks like a zone ID, try it
    if zone_identifier.startswith("Z"):
        try:
            route53_client.get_hosted_zone(Id=zone_identifier)
            return zone_identifier
        except ClientError:
            pass
    
    # Try to find by domain name
    try:
        paginator = route53_client.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                zone_name = zone.get("Name")
                zone_id = zone.get("Id").split("/")[-1]
                if zone_name == zone_identifier or zone_name.rstrip(".") == zone_identifier.rstrip("."):
                    return zone_id
                if zone_id == zone_identifier:
                    return zone_id
    except ClientError:
        pass
    
    return None


def run_route53_all(args):
    """Collect all Route53 data for a hosted zone into a single file."""
    zone_identifier = getattr(args, "zone", None)
    
    if not zone_identifier:
        print("❌ Error: --zone parameter is required")
        print("   Usage: ventra collect route53 all --case <case> --zone <zone_id_or_domain>")
        return
    
    print(f"[+] Route53 All Collector")
    print(f"    Zone:        {zone_identifier}")
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
        route53_client = _get_route53_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Route53 client: {e}")
        return
    
    try:
        # Resolve zone ID
        print(f"[+] Resolving zone identifier...")
        zone_id = _resolve_zone_id(route53_client, zone_identifier)
        if not zone_id:
            print(f"❌ Error: Could not find zone with identifier: {zone_identifier}")
            return
        
        print(f"    ✓ Found zone ID: {zone_id}\n")
        
        # Collect all data
        all_data = {
            "ZoneId": zone_id,
            "ZoneInfo": None,
            "Records": [],
            "QueryLogs": None,
        }
        
        # 1. Get hosted zone info
        print(f"[+] Collecting hosted zone information...")
        try:
            zone_response = route53_client.get_hosted_zone(Id=zone_id)
            all_data["ZoneInfo"] = {
                "HostedZone": zone_response.get("HostedZone", {}),
                "DelegationSet": zone_response.get("DelegationSet", {}),
                "VPCs": zone_response.get("VPCs", []),
            }
            print(f"    ✓ Collected zone info")
        except Exception as e:
            print(f"    ⚠ Error collecting zone info: {e} (continuing)")
        
        # 2. Get DNS records
        print(f"[+] Collecting DNS records...")
        try:
            paginator = route53_client.get_paginator("list_resource_record_sets")
            for page in paginator.paginate(HostedZoneId=zone_id):
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
                    all_data["Records"].append(record_info)
            print(f"    ✓ Collected {len(all_data['Records'])} record(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting records: {e} (continuing)")
        
        # 3. Get query logs (if configured)
        print(f"[+] Collecting query logs configuration...")
        try:
            logs_paginator = route53_client.get_paginator("list_query_logging_configs")
            for page in logs_paginator.paginate():
                configs = page.get("QueryLoggingConfigs", [])
                # Filter configs for this specific hosted zone
                zone_configs = [c for c in configs if c.get("HostedZoneId") == zone_id or c.get("HostedZoneId") == f"/hostedzone/{zone_id}"]
                if zone_configs:
                    all_data["QueryLogs"] = zone_configs
                    print(f"    ✓ Found {len(zone_configs)} query logging config(s)")
                    break
            if not all_data["QueryLogs"]:
                print(f"    ⚠ No query logging configured for this zone")
        except Exception as e:
            print(f"    ⚠ Error collecting query logs: {e} (continuing)")
        
        # Get zone name for filename
        zone_name = all_data["ZoneInfo"].get("HostedZone", {}).get("Name", zone_id).rstrip(".").replace(".", "_")
        filename = f"route53_{zone_name}_all.json"
        
        # Save combined file
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all Route53 data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

