"""
CloudWatch Alarms Collector
Collects CloudWatch alarms and their configurations.
Alarm tampering is a forensic indicator.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_cloudwatch_client(region):
    """CloudWatch client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("cloudwatch")


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


def run_cloudwatch_alarms(args):
    """Collect CloudWatch alarms."""
    print(f"[+] CloudWatch Alarms Collector")
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
        cw_client = _get_cloudwatch_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch client: {e}")
        return
    
    try:
        alarms_data = {
            "alarms": [],
        }
        
        print("[+] Listing all alarms...")
        paginator = cw_client.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                alarm_info = {
                    "AlarmName": alarm.get("AlarmName"),
                    "AlarmArn": alarm.get("AlarmArn"),
                    "AlarmDescription": alarm.get("AlarmDescription"),
                    "AlarmConfigurationUpdatedTimestamp": str(alarm.get("AlarmConfigurationUpdatedTimestamp", "")),
                    "ActionsEnabled": alarm.get("ActionsEnabled"),
                    "OKActions": alarm.get("OKActions", []),
                    "AlarmActions": alarm.get("AlarmActions", []),
                    "InsufficientDataActions": alarm.get("InsufficientDataActions", []),
                    "StateValue": alarm.get("StateValue"),
                    "StateReason": alarm.get("StateReason"),
                    "StateUpdatedTimestamp": str(alarm.get("StateUpdatedTimestamp", "")),
                    "StateTransitionedTimestamp": str(alarm.get("StateTransitionedTimestamp", "")),
                    "MetricName": alarm.get("MetricName"),
                    "Namespace": alarm.get("Namespace"),
                    "Statistic": alarm.get("Statistic"),
                    "ExtendedStatistic": alarm.get("ExtendedStatistic"),
                    "Dimensions": alarm.get("Dimensions", []),
                    "Period": alarm.get("Period"),
                    "Unit": alarm.get("Unit"),
                    "EvaluationPeriods": alarm.get("EvaluationPeriods"),
                    "DatapointsToAlarm": alarm.get("DatapointsToAlarm"),
                    "Threshold": alarm.get("Threshold"),
                    "ComparisonOperator": alarm.get("ComparisonOperator"),
                    "TreatMissingData": alarm.get("TreatMissingData"),
                    "EvaluateLowSampleCountPercentile": alarm.get("EvaluateLowSampleCountPercentile"),
                }
                alarms_data["alarms"].append(alarm_info)
        
        alarms_data["total_alarms"] = len(alarms_data["alarms"])
        
        # Count by state
        state_counts = {}
        for alarm in alarms_data["alarms"]:
            state = alarm.get("StateValue", "UNKNOWN")
            state_counts[state] = state_counts.get(state, 0) + 1
        
        alarms_data["state_counts"] = state_counts
        
        print(f"    ✓ Found {alarms_data['total_alarms']} alarm(s)")
        for state, count in state_counts.items():
            print(f"      {state}: {count}")
        
        # Save single combined file
        filename = "cloudwatch_alarms.json"
        filepath = _save_json_file(output_dir, filename, alarms_data)
        if filepath:
            print(f"\n[✓] Saved alarms → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

