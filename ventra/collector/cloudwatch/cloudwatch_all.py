"""
CloudWatch All Collector
Collects all CloudWatch information (log groups, alarms, events, dashboards) into a single combined file.
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


def _get_cloudwatch_logs_client(region):
    """CloudWatch Logs client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("logs")


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


def run_cloudwatch_all(args):
    """Collect all CloudWatch data into a single file."""
    print(f"[+] CloudWatch All Collector")
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
        logs_client = _get_cloudwatch_logs_client(args.region)
        events_client = _get_events_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch clients: {e}")
        return
    
    try:
        all_data = {
            "LogGroups": [],
            "Alarms": [],
            "Events": [],
            "Dashboards": [],
        }
        
        # 1. Collect log groups
        print("[+] Collecting CloudWatch log groups...")
        try:
            paginator = logs_client.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for log_group in page.get("logGroups", []):
                    log_group_info = {
                        "logGroupName": log_group.get("logGroupName"),
                        "creationTime": log_group.get("creationTime"),
                        "retentionInDays": log_group.get("retentionInDays"),
                        "metricFilterCount": log_group.get("metricFilterCount", 0),
                        "arn": log_group.get("arn"),
                        "storedBytes": log_group.get("storedBytes", 0),
                        "kmsKeyId": log_group.get("kmsKeyId"),
                    }
                    all_data["LogGroups"].append(log_group_info)
            print(f"    ✓ Found {len(all_data['LogGroups'])} log group(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting log groups: {e} (continuing)")
        
        # 2. Collect alarms
        print("[+] Collecting CloudWatch alarms...")
        try:
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
                    all_data["Alarms"].append(alarm_info)
            print(f"    ✓ Found {len(all_data['Alarms'])} alarm(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting alarms: {e} (continuing)")
        
        # 3. Collect EventBridge rules
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
                    
                    # Get targets
                    try:
                        targets_response = events_client.list_targets_by_rule(Rule=rule_name)
                        rule_info["Targets"] = targets_response.get("Targets", [])
                    except Exception:
                        pass
                    
                    all_data["Events"].append(rule_info)
            print(f"    ✓ Found {len(all_data['Events'])} EventBridge rule(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting events: {e} (continuing)")
        
        # 4. Collect dashboards
        print("[+] Collecting CloudWatch dashboards...")
        try:
            response = cw_client.list_dashboards()
            for dashboard in response.get("DashboardEntries", []):
                dashboard_name = dashboard.get("DashboardName")
                dashboard_info = {
                    "DashboardName": dashboard_name,
                    "DashboardArn": dashboard.get("DashboardArn"),
                    "LastModified": str(dashboard.get("LastModified", "")),
                    "Size": dashboard.get("Size", 0),
                    "DashboardBody": None,
                }
                
                # Get dashboard body
                try:
                    dashboard_response = cw_client.get_dashboard(DashboardName=dashboard_name)
                    dashboard_info["DashboardBody"] = dashboard_response.get("DashboardBody")
                except Exception:
                    pass
                
                all_data["Dashboards"].append(dashboard_info)
            print(f"    ✓ Found {len(all_data['Dashboards'])} dashboard(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting dashboards: {e} (continuing)")
        
        # Summary
        all_data["total_log_groups"] = len(all_data["LogGroups"])
        all_data["total_alarms"] = len(all_data["Alarms"])
        all_data["total_events"] = len(all_data["Events"])
        all_data["total_dashboards"] = len(all_data["Dashboards"])
        
        # Count alarms by state
        alarm_state_counts = {}
        for alarm in all_data["Alarms"]:
            state = alarm.get("StateValue", "UNKNOWN")
            alarm_state_counts[state] = alarm_state_counts.get(state, 0) + 1
        all_data["alarm_state_counts"] = alarm_state_counts
        
        print(f"\n    Summary:")
        print(f"      Log Groups: {all_data['total_log_groups']}")
        print(f"      Alarms: {all_data['total_alarms']}")
        print(f"      EventBridge Rules: {all_data['total_events']}")
        print(f"      Dashboards: {all_data['total_dashboards']}")
        
        # Save combined file
        filename = "cloudwatch_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all CloudWatch data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
