"""
EventBridge Targets Collector
Collects targets for EventBridge rules - attackers use these for exfiltration and backdoors.
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


def run_eventbridge_targets(args):
    """Collect EventBridge rule targets."""
    print(f"[+] EventBridge Targets Collector")
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
        events_client = _get_events_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EventBridge client: {e}")
        return
    
    try:
        targets_data = {
            "rules_with_targets": [],
        }
        
        print("[+] Listing all EventBridge rules and their targets...")
        paginator = events_client.get_paginator("list_rules")
        rule_count = 0
        
        for page in paginator.paginate():
            for rule in page.get("Rules", []):
                rule_name = rule.get("Name")
                rule_count += 1
                
                try:
                    targets_response = events_client.list_targets_by_rule(Rule=rule_name)
                    targets = targets_response.get("Targets", [])
                    
                    if targets:
                        rule_targets_info = {
                            "RuleName": rule_name,
                            "RuleArn": rule.get("Arn"),
                            "RuleState": rule.get("State"),
                            "Targets": [],
                        }
                        
                        for target in targets:
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
                            rule_targets_info["Targets"].append(target_info)
                        
                        targets_data["rules_with_targets"].append(rule_targets_info)
                except ClientError as e:
                    print(f"      ⚠ Error getting targets for {rule_name}: {e}")
        
        targets_data["total_rules_checked"] = rule_count
        targets_data["total_rules_with_targets"] = len(targets_data["rules_with_targets"])
        
        print(f"    ✓ Checked {rule_count} rule(s)")
        print(f"    ✓ Found {targets_data['total_rules_with_targets']} rule(s) with targets")
        
        # Save single combined file
        filename = "eventbridge_targets.json"
        filepath = _save_json_file(output_dir, filename, targets_data)
        if filepath:
            print(f"\n[✓] Saved targets → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

