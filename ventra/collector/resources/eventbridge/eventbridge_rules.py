"""
EventBridge Rules Collector
Collects EventBridge rules - ABSOLUTELY ESSENTIAL for DFIR.
Attackers use malicious scheduled rules for persistence, backdoor automation workflows, and event triggers.
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


def run_eventbridge_rules(args):
    """Collect EventBridge rules."""
    print(f"[+] EventBridge Rules Collector")
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
        rules_data = {
            "rules": [],
        }
        
        print("[+] Listing all EventBridge rules...")
        paginator = events_client.get_paginator("list_rules")
        for page in paginator.paginate():
            for rule in page.get("Rules", []):
                rule_name = rule.get("Name")
                
                rule_info = {
                    "Name": rule_name,
                    "Arn": rule.get("Arn"),
                    "Description": rule.get("Description"),
                    "State": rule.get("State"),
                    "ScheduleExpression": rule.get("ScheduleExpression"),
                    "EventPattern": rule.get("EventPattern"),
                    "EventBusName": rule.get("EventBusName"),
                    "CreatedBy": rule.get("CreatedBy"),
                    "ManagedBy": rule.get("ManagedBy"),
                }
                
                rules_data["rules"].append(rule_info)
        
        rules_data["total_rules"] = len(rules_data["rules"])
        
        # Count by state
        state_counts = {}
        for rule in rules_data["rules"]:
            state = rule.get("State", "UNKNOWN")
            state_counts[state] = state_counts.get(state, 0) + 1
        
        rules_data["state_counts"] = state_counts
        
        print(f"    ✓ Found {rules_data['total_rules']} rule(s)")
        for state, count in state_counts.items():
            print(f"      {state}: {count}")
        
        # Save single combined file
        filename = "eventbridge_rules.json"
        filepath = _save_json_file(output_dir, filename, rules_data)
        if filepath:
            print(f"\n[✓] Saved rules → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

