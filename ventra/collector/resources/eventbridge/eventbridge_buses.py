"""
EventBridge Buses Collector
Collects EventBridge event buses and their configurations.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_events_client(region):
    """EventBridge client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("events")


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


def run_eventbridge_buses(args):
    """Collect EventBridge event buses."""
    print(f"[+] EventBridge Buses Collector")
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
        events_client = _get_events_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EventBridge client: {e}")
        return
    
    try:
        buses_data = {
            "event_buses": [],
        }
        
        print("[+] Listing all EventBridge event buses...")
        paginator = events_client.get_paginator("list_event_buses")
        for page in paginator.paginate():
            for bus in page.get("EventBuses", []):
                bus_name = bus.get("Name")
                
                bus_info = {
                    "Name": bus_name,
                    "Arn": bus.get("Arn"),
                    "Policy": None,
                }
                
                # Get event bus policy
                try:
                    policy_response = events_client.describe_event_bus(Name=bus_name)
                    bus_info["Policy"] = json.loads(policy_response.get("Policy", "{}")) if policy_response.get("Policy") else None
                except ClientError as e:
                    print(f"      ⚠ Error getting policy for {bus_name}: {e}")
                
                buses_data["event_buses"].append(bus_info)
        
        buses_data["total_buses"] = len(buses_data["event_buses"])
        print(f"    ✓ Found {buses_data['total_buses']} event bus/buses")
        
        # Save single combined file
        filename = "eventbridge_buses.json"
        filepath = _save_json_file(output_dir, filename, buses_data)
        if filepath:
            print(f"\n[✓] Saved event buses → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

