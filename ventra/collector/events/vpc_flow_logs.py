"""
VPC Flow Logs Collector (Events Domain)
Collects VPC flow log events from CloudWatch Logs.
"""
import os
import json
import re
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_ec2_client(region):
    """EC2 client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("ec2")


def _get_cloudwatch_logs_client(region):
    """CloudWatch Logs client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("logs")


def _resolve_output_dir(args):
    """Resolve output directory - use case_dir if available, otherwise fallback."""
    if hasattr(args, "case_dir") and args.case_dir:
        output_base = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_base = args.output
    else:
        output_base = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_base = os.path.join(output_base, "events")
    os.makedirs(output_base, exist_ok=True)
    return output_base


def run_vpc_flow_logs(args):
    """Collect VPC flow log configuration and optionally recent log events."""
    print("[+] VPC Flow Logs Collector (Events)")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting AWS clients: {e}")
        return
    
    try:
        print("[+] Describing flow logs...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "resource-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_flow_logs(Filters=filters if filters else None)
        flow_logs = response.get("FlowLogs", [])
        
        if not flow_logs:
            print("    ⚠ No flow logs configured in this region")
            return
        
        print(f"    ✓ Found {len(flow_logs)} flow log configuration(s)")
        
        output_dir = _resolve_output_dir(args)
        hours = getattr(args, "hours", None)
        
        # Collect log events if hours specified
        if hours:
            print(f"[+] Collecting flow log events from last {hours} hours...")
            for flow_log in flow_logs:
                log_destination = flow_log.get("LogDestination")
                if not log_destination:
                    continue
                
                # Extract log group name from ARN
                # Format: arn:aws:logs:region:account:log-group:/aws/vpc/flowlogs
                log_group_match = re.search(r'log-group:(.+?)(?::|$)', log_destination)
                if log_group_match:
                    log_group_name = log_group_match.group(1)
                    
                    print(f"    Collecting from log group: {log_group_name}")
                    end_time = datetime.now(timezone.utc)
                    start_time = end_time - timedelta(hours=hours)
                    
                    start_timestamp = int(start_time.timestamp() * 1000)
                    end_timestamp = int(end_time.timestamp() * 1000)
                    
                    events = []
                    try:
                        paginator = logs_client.get_paginator("filter_log_events")
                        for page in paginator.paginate(
                            logGroupName=log_group_name,
                            startTime=start_timestamp,
                            endTime=end_timestamp,
                        ):
                            for event in page.get("events", []):
                                events.append({
                                    "timestamp": event.get("timestamp"),
                                    "message": event.get("message"),
                                    "logStreamName": event.get("logStreamName"),
                                })
                        
                        if events:
                            safe_name = log_group_name.replace("/", "_")
                            filename = f"vpc_flow_logs_{safe_name}_{hours}h.json"
                            filepath = os.path.join(output_dir, filename)
                            with open(filepath, "w", encoding="utf-8") as f:
                                json.dump({"log_group": log_group_name, "events": events, "total": len(events)}, f, indent=2)
                            print(f"      ✓ Saved {len(events)} events → {filepath}")
                    except Exception as e:
                        print(f"      ⚠ Error collecting events: {e}")
        
        # Save flow log configurations
        filename = "vpc_flow_logs.json"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({"flow_logs": flow_logs, "total": len(flow_logs)}, f, indent=2, default=str)
        print(f"\n[✓] Saved flow log configurations → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

