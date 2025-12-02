"""
CloudWatch Log Group Collector
Collects log group metadata, log streams, and log events from a specific CloudWatch log group.
"""
import os
import json
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_cloudwatch_logs_client(region):
    """CloudWatch Logs client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("logs")


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


def run_cloudwatch_log_group(args):
    """Collect log group metadata, log streams, and log events from a CloudWatch log group."""
    log_group_name = args.group
    hours = getattr(args, "hours", None)
    
    if not log_group_name:
        print("❌ Error: --group parameter is required")
        print("   Usage: ventra collect events cloudwatch --case <case> --group <log-group-name> [--hours <N>]")
        return
    
    print(f"[+] CloudWatch Log Group Collector")
    print(f"    Log Group:   {log_group_name}")
    print(f"    Region:      {args.region}")
    if hours:
        print(f"    Hours:       {hours} (collecting events from last {hours} hours)")
    print()
    
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
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch Logs client: {e}")
        return
    
    try:
        # Initialize comprehensive data structure
        logs_data = {
            "logGroupName": log_group_name,
            "logGroupMetadata": {},
            "logStreams": [],
            "logEvents": [],
        }
        
        # 1. Collect log group metadata
        print("[+] Collecting log group metadata...")
        try:
            log_groups_response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
            log_groups = log_groups_response.get("logGroups", [])
            
            # Find exact match
            log_group_info = None
            for lg in log_groups:
                if lg.get("logGroupName") == log_group_name:
                    log_group_info = lg
                    break
            
            if log_group_info:
                logs_data["logGroupMetadata"] = {
                    "logGroupName": log_group_info.get("logGroupName"),
                    "creationTime": log_group_info.get("creationTime"),
                    "retentionInDays": log_group_info.get("retentionInDays"),
                    "metricFilterCount": log_group_info.get("metricFilterCount", 0),
                    "arn": log_group_info.get("arn"),
                    "storedBytes": log_group_info.get("storedBytes", 0),
                    "kmsKeyId": log_group_info.get("kmsKeyId"),
                }
                print(f"    ✓ Collected log group metadata")
                print(f"      - Creation Time: {log_group_info.get('creationTime')}")
                print(f"      - Retention: {log_group_info.get('retentionInDays')} days" if log_group_info.get('retentionInDays') else "      - Retention: Never expire")
                print(f"      - Stored Bytes: {log_group_info.get('storedBytes', 0):,}")
            else:
                print(f"    ⚠ Log group '{log_group_name}' not found")
                logs_data["logGroupMetadata"] = {"error": "Log group not found"}
        except ClientError as e:
            print(f"    ⚠ Error getting log group metadata: {e}")
            logs_data["logGroupMetadata"] = {"error": str(e)}
        
        # 2. Collect log streams
        print("[+] Collecting log streams...")
        try:
            paginator = logs_client.get_paginator("describe_log_streams")
            for page in paginator.paginate(logGroupName=log_group_name, orderBy="LastEventTime", descending=True):
                for stream in page.get("logStreams", []):
                    stream_info = {
                        "logStreamName": stream.get("logStreamName"),
                        "creationTime": stream.get("creationTime"),
                        "firstEventTimestamp": stream.get("firstEventTimestamp"),
                        "lastEventTimestamp": stream.get("lastEventTimestamp"),
                        "lastIngestionTime": stream.get("lastIngestionTime"),
                        "uploadSequenceToken": stream.get("uploadSequenceToken"),
                        "arn": stream.get("arn"),
                        "storedBytes": stream.get("storedBytes", 0),
                    }
                    logs_data["logStreams"].append(stream_info)
            
            logs_data["total_streams"] = len(logs_data["logStreams"])
            print(f"    ✓ Found {logs_data['total_streams']} log stream(s)")
        except ClientError as e:
            print(f"    ⚠ Error listing log streams: {e}")
            logs_data["total_streams"] = 0
        
        # 3. Collect log events if hours specified
        if hours:
            print(f"[+] Collecting log events from last {hours} hours...")
            try:
                end_time = datetime.now(timezone.utc)
                start_time = end_time - timedelta(hours=hours)
                
                start_timestamp = int(start_time.timestamp() * 1000)
                end_timestamp = int(end_time.timestamp() * 1000)
                
                paginator = logs_client.get_paginator("filter_log_events")
                event_count = 0
                for page in paginator.paginate(
                    logGroupName=log_group_name,
                    startTime=start_timestamp,
                    endTime=end_timestamp,
                ):
                    for event in page.get("events", []):
                        event_info = {
                            "logStreamName": event.get("logStreamName"),
                            "timestamp": event.get("timestamp"),
                            "message": event.get("message"),
                            "ingestionTime": event.get("ingestionTime"),
                            "eventId": event.get("eventId"),
                        }
                        logs_data["logEvents"].append(event_info)
                        event_count += 1
                        
                        if event_count % 1000 == 0:
                            print(f"    ... Collected {event_count} events so far...")
                
                logs_data["total_events"] = len(logs_data["logEvents"])
                print(f"    ✓ Collected {logs_data['total_events']} log event(s)")
            except ClientError as e:
                print(f"    ⚠ Error collecting log events: {e}")
                logs_data["total_events"] = 0
                logs_data["events_error"] = str(e)
        else:
            logs_data["total_events"] = 0
            print(f"    ⚠ No --hours specified, skipping event collection")
            print(f"    💡 Tip: Use --hours <N> to collect log events")
        
        # Save comprehensive data
        safe_group_name = log_group_name.replace("/", "_").replace(" ", "_")
        filename = f"cloudwatch_log_group_{safe_group_name}.json"
        if hours:
            filename = f"cloudwatch_log_group_{safe_group_name}_{hours}h.json"
        
        filepath = _save_json_file(output_dir, filename, logs_data)
        if filepath:
            print(f"\n[✓] Saved CloudWatch log data → {filepath}")
            print(f"    Log Group Metadata: ✓")
            print(f"    Log Streams: {logs_data.get('total_streams', 0)}")
            print(f"    Log Events: {logs_data.get('total_events', 0)}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

