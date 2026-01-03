"""
CloudWatch Log Groups Collector
Collects all CloudWatch log groups, their metadata, and optionally log events from each group.
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


def _collect_log_events(logs_client, log_group_name, hours):
    """Collect log events from a specific log group."""
    events = []
    streams = []
    
    try:
        # List log streams
        paginator = logs_client.get_paginator("describe_log_streams")
        for page in paginator.paginate(logGroupName=log_group_name, orderBy="LastEventTime", descending=True):
            for stream in page.get("logStreams", []):
                stream_info = {
                    "logStreamName": stream.get("logStreamName"),
                    "creationTime": stream.get("creationTime"),
                    "firstEventTimestamp": stream.get("firstEventTimestamp"),
                    "lastEventTimestamp": stream.get("lastEventTimestamp"),
                    "lastIngestionTime": stream.get("lastIngestionTime"),
                    "arn": stream.get("arn"),
                    "storedBytes": stream.get("storedBytes", 0),
                }
                streams.append(stream_info)
        
        # If hours is omitted, collect all available events (may be large).
        collect_all = hours is None
        end_time = datetime.now(timezone.utc)
        if collect_all:
            start_timestamp = 0
        else:
            start_time = end_time - timedelta(hours=hours)
            start_timestamp = int(start_time.timestamp() * 1000)
        end_timestamp = int(end_time.timestamp() * 1000)

        max_events_total = 50_000
        event_count = 0
        truncated = False

        paginator = logs_client.get_paginator("filter_log_events")
        for page in paginator.paginate(
            logGroupName=log_group_name,
            startTime=start_timestamp,
            endTime=end_timestamp,
        ):
            for event in page.get("events", []):
                events.append(
                    {
                        "logStreamName": event.get("logStreamName"),
                        "timestamp": event.get("timestamp"),
                        "message": event.get("message"),
                        "ingestionTime": event.get("ingestionTime"),
                        "eventId": event.get("eventId"),
                    }
                )
                event_count += 1

                if event_count % 1000 == 0:
                    print(f"      ... Collected {event_count} events from {log_group_name}...")

                if event_count >= max_events_total:
                    truncated = True
                    break
            if truncated:
                break
        
        return {
            "logStreams": streams,
            "logEvents": events,
            "total_streams": len(streams),
            "total_events": len(events),
            "events_truncated": truncated,
        }
    except Exception as e:
        print(f"      ⚠ Error collecting events from {log_group_name}: {e}")
        return {
            "logStreams": streams,
            "logEvents": [],
            "total_streams": len(streams),
            "total_events": 0,
            "error": str(e),
        }


def run_cloudwatch_log_groups(args):
    """Collect all CloudWatch log groups and optionally their log events."""
    hours = getattr(args, "hours", None)
    collect_all = hours is None
    
    print(f"[+] CloudWatch Log Groups Collector")
    print(f"    Region:      {args.region}")
    if collect_all:
        print("    Hours:       (ALL AVAILABLE - may be large)")
    else:
        print(f"    Hours:       {hours} (collecting events from each log group)")
    print()
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")

    # Logs collectors must write under the case's logs/ directory
    output_dir = os.path.join(output_dir, "logs")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch Logs client: {e}")
        return
    
    try:
        log_groups_data = {
            "log_groups": [],
        }
        
        print("[+] Listing all log groups...")
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
                log_groups_data["log_groups"].append(log_group_info)
        
        log_groups_data["total_log_groups"] = len(log_groups_data["log_groups"])
        print(f"    ✓ Found {log_groups_data['total_log_groups']} log group(s)")
        
        # Collect log events from each log group (if hours omitted, collect all available)
        if collect_all:
            print("\n[+] Collecting log events from each log group (ALL AVAILABLE)...")
        else:
            print(f"\n[+] Collecting log events from each log group (last {hours} hours)...")
            total_events = 0
            
            for i, log_group_info in enumerate(log_groups_data["log_groups"], 1):
                log_group_name = log_group_info["logGroupName"]
                print(f"    [{i}/{log_groups_data['total_log_groups']}] Processing: {log_group_name}")
                
                events_data = _collect_log_events(logs_client, log_group_name, hours)
                log_group_info["logStreams"] = events_data["logStreams"]
                log_group_info["logEvents"] = events_data["logEvents"]
                log_group_info["total_streams"] = events_data["total_streams"]
                log_group_info["total_events"] = events_data["total_events"]
                log_group_info["events_truncated"] = events_data.get("events_truncated", False)
                
                if "error" in events_data:
                    log_group_info["collection_error"] = events_data["error"]
                
                total_events += events_data["total_events"]
                print(f"      ✓ Collected {events_data['total_events']} event(s) from {events_data['total_streams']} stream(s)")
            
            log_groups_data["total_events_collected"] = total_events
            print(f"\n    ✓ Total events collected: {total_events}")
        
        # Save single combined file
        filename = "cloudwatch_log_groups.json"
        if not collect_all:
            filename = f"cloudwatch_log_groups_{hours}h.json"
        
        filepath = _save_json_file(output_dir, filename, log_groups_data)
        if filepath:
            print(f"\n[✓] Saved log groups → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

