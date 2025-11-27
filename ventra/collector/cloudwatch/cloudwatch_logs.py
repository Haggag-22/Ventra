"""
CloudWatch Logs Collector
Collects log events from a specific log group, optionally filtered by time range.
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


def run_cloudwatch_logs(args):
    """Collect log events from a CloudWatch log group."""
    log_group_name = args.group
    hours = getattr(args, "hours", None)
    
    print(f"[+] CloudWatch Logs Collector")
    print(f"    Log Group:   {log_group_name}")
    if hours:
        print(f"    Hours:      {hours}")
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
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch Logs client: {e}")
        return
    
    try:
        logs_data = {
            "logGroupName": log_group_name,
            "logStreams": [],
            "logEvents": [],
        }
        
        # List log streams
        print("[+] Listing log streams...")
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
        
        # Collect log events if hours specified
        if hours:
            print(f"[+] Collecting log events from last {hours} hours...")
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
        else:
            logs_data["total_events"] = 0
            print(f"    ⚠ No --hours specified, skipping event collection")
        
        # Save single combined file
        safe_group_name = log_group_name.replace("/", "_").replace(" ", "_")
        filename = f"cloudwatch_logs_{safe_group_name}.json"
        if hours:
            filename = f"cloudwatch_logs_{safe_group_name}_{hours}h.json"
        
        filepath = _save_json_file(output_dir, filename, logs_data)
        if filepath:
            print(f"\n[✓] Saved log data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
