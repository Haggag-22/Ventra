"""
EventBridge All Collector
Collects all EventBridge information (rules, targets, buses) into a single combined file.
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


def run_eventbridge_all(args):
    """Collect all EventBridge data into a single file."""
    print(f"[+] EventBridge All Collector")
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
        all_data = {
            "Rules": [],
            "Buses": [],
        }
        
        # 1. Collect rules with targets
        print("[+] Collecting EventBridge rules...")
        try:
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
                        "Targets": [],
                    }
                    
                    # Get targets for this rule
                    try:
                        targets_response = events_client.list_targets_by_rule(Rule=rule_name)
                        for target in targets_response.get("Targets", []):
                            target_info = {
                                "Id": target.get("Id"),
                                "Arn": target.get("Arn"),
                                "RoleArn": target.get("RoleArn"),
                                "Input": target.get("Input"),
                                "InputPath": target.get("InputPath"),
                                "InputTransformer": target.get("InputTransformer"),
                                "KinesisParameters": target.get("KinesisParameters"),
                                "RunCommandParameters": target.get("RunCommandParameters"),
                                "EcsParameters": target.get("EcsParameters"),
                                "BatchParameters": target.get("BatchParameters"),
                                "SqsParameters": target.get("SqsParameters"),
                                "HttpParameters": target.get("HttpParameters"),
                                "RedshiftDataParameters": target.get("RedshiftDataParameters"),
                                "SageMakerPipelineParameters": target.get("SageMakerPipelineParameters"),
                                "DeadLetterConfig": target.get("DeadLetterConfig"),
                                "RetryPolicy": target.get("RetryPolicy"),
                            }
                            rule_info["Targets"].append(target_info)
                    except Exception as e:
                        print(f"      ⚠ Error getting targets for {rule_name}: {e} (continuing)")
                    
                    all_data["Rules"].append(rule_info)
            
            print(f"    ✓ Found {len(all_data['Rules'])} rule(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting rules: {e} (continuing)")
        
        # 2. Collect event buses
        print("[+] Collecting EventBridge event buses...")
        try:
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
                    except Exception as e:
                        print(f"      ⚠ Error getting policy for {bus_name}: {e} (continuing)")
                    
                    all_data["Buses"].append(bus_info)
            
            print(f"    ✓ Found {len(all_data['Buses'])} event bus/buses")
        except Exception as e:
            print(f"    ⚠ Error collecting buses: {e} (continuing)")
        
        # Summary
        all_data["total_rules"] = len(all_data["Rules"])
        all_data["total_buses"] = len(all_data["Buses"])
        
        # Count rules by state
        state_counts = {}
        for rule in all_data["Rules"]:
            state = rule.get("State", "UNKNOWN")
            state_counts[state] = state_counts.get(state, 0) + 1
        all_data["rule_state_counts"] = state_counts
        
        # Count rules with targets
        rules_with_targets = sum(1 for rule in all_data["Rules"] if rule.get("Targets"))
        all_data["rules_with_targets"] = rules_with_targets
        
        print(f"\n    Summary:")
        print(f"      Rules: {all_data['total_rules']}")
        print(f"      Rules with targets: {rules_with_targets}")
        print(f"      Event buses: {all_data['total_buses']}")
        
        # Save combined file
        filename = "eventbridge_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all EventBridge data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
