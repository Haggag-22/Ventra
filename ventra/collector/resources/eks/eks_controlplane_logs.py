"""
EKS Control Plane Logs Collector
Collects control plane logs if enabled.
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


def run_eks_controlplane_logs(args):
    """Collect EKS control plane logs."""
    cluster_name = args.cluster
    hours = getattr(args, "hours", None)
    collect_all = hours is None
    
    print(f"[+] EKS Control Plane Logs Collector")
    print(f"    Cluster:     {cluster_name}")
    print(f"    Hours:       (ALL AVAILABLE - may be large)" if collect_all else f"    Hours:       {hours}")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")

    # Resources collectors must write under the case's resources/ directory
    output_dir = os.path.join(output_dir, "resources")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch Logs client: {e}")
        return
    
    try:
        logs_data = {
            "cluster": cluster_name,
            "log_groups": [],
        }
        
        # EKS control plane logs are in CloudWatch Logs
        log_group_prefix = f"/aws/eks/{cluster_name}/cluster"
        log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
        
        print("[+] Collecting control plane logs...")
        end_time = datetime.now(timezone.utc)
        start_time = None if collect_all else (end_time - timedelta(hours=hours))
        
        for log_type in log_types:
            log_group_name = f"{log_group_prefix}/{log_type}"
            print(f"[+] Checking log group: {log_group_name}")
            
            try:
                # Check if log group exists
                logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
                
                # Get log streams
                streams_response = logs_client.describe_log_streams(
                    logGroupName=log_group_name,
                    orderBy="LastEventTime",
                    descending=True,
                    limit=10
                )
                
                log_group_info = {
                    "LogGroupName": log_group_name,
                    "LogType": log_type,
                    "Streams": [],
                    "Events": [],
                }
                
                # Collect log events
                start_ts = 0 if collect_all else int(start_time.timestamp() * 1000)
                end_ts = int(end_time.timestamp() * 1000)

                max_events_per_group = 50_000
                events_truncated = False
                event_count = 0

                try:
                    paginator = logs_client.get_paginator("filter_log_events")
                    for page in paginator.paginate(
                        logGroupName=log_group_name,
                        startTime=start_ts,
                        endTime=end_ts,
                    ):
                        evs = page.get("events", []) or []
                        log_group_info["Events"].extend(evs)
                        event_count += len(evs)
                        if event_count >= max_events_per_group:
                            events_truncated = True
                            log_group_info["Events"] = log_group_info["Events"][:max_events_per_group]
                            break
                except ClientError as e:
                    print(f"      ⚠ Error getting events: {e}")

                # Keep stream metadata (top 10) for context
                for stream in streams_response.get("logStreams", [])[:10]:
                    log_group_info["Streams"].append(
                        {
                            "LogStreamName": stream.get("logStreamName"),
                            "LastEventTime": str(stream.get("lastEventTime", "")),
                        }
                    )
                log_group_info["EventsTruncated"] = events_truncated
                
                if log_group_info["Streams"]:
                    logs_data["log_groups"].append(log_group_info)
                    print(f"    ✓ Found {len(log_group_info['Events'])} event(s)" + (" (TRUNCATED)" if events_truncated else ""))
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "ResourceNotFoundException":
                    print(f"    ⚠ Log group not found (logging may not be enabled)")
                else:
                    print(f"    ⚠ Error: {e}")
        
        logs_data["total_log_groups"] = len(logs_data["log_groups"])
        total_events = sum(len(lg["Events"]) for lg in logs_data["log_groups"])
        logs_data["total_events"] = total_events
        
        # Save single combined file
        safe_name = cluster_name.replace(":", "_").replace("/", "_")
        filename = f"eks_controlplane_logs_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, logs_data)
        if filepath:
            print(f"\n[✓] Saved control plane logs → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

