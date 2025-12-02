"""
Route53 Query Logs Collector
Collects Route53 query logging configurations.
Query logs reveal DNS queries which can show C2 communication patterns.
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


def run_route53_resolver_query_logs(args):
    """Collect Route53 Resolver query logging configurations."""
    print(f"[+] Route53 Resolver Query Logs Collector")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "events")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        route53_client = _get_route53_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Route53 client: {e}")
        return
    
    try:
        query_logs_data = {
            "query_logging_configs": [],
        }
        
        print("[+] Listing all query logging configurations...")
        paginator = route53_client.get_paginator("list_query_logging_configs")
        for page in paginator.paginate():
            for config in page.get("QueryLoggingConfigs", []):
                config_id = config.get("Id")
                
                config_info = {
                    "Id": config_id,
                    "HostedZoneId": config.get("HostedZoneId"),
                    "CloudWatchLogsLogGroupArn": config.get("CloudWatchLogsLogGroupArn"),
                }
                
                # Get detailed config
                try:
                    config_details = route53_client.get_query_logging_config(Id=config_id)
                    config_info["QueryLoggingConfig"] = config_details.get("QueryLoggingConfig", {})
                except ClientError as e:
                    print(f"      ⚠ Error getting config details: {e}")
                
                query_logs_data["query_logging_configs"].append(config_info)
        
        query_logs_data["total_configs"] = len(query_logs_data["query_logging_configs"])
        print(f"    ✓ Found {query_logs_data['total_configs']} query logging configuration(s)")
        
        # Save single combined file
        filename = "route53_resolver_query_logs.json"
        filepath = _save_json_file(output_dir, filename, query_logs_data)
        if filepath:
            print(f"\n[✓] Saved query log configs → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

