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
    hours = getattr(args, "hours", 24)
    
    print(f"[+] EKS Control Plane Logs Collector")
    print(f"    Cluster:     {cluster_name}")
    print(f"    Hours:       {hours}")
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
            "cluster": cluster_name,
            "log_groups": [],
        }
        
        # EKS control plane logs are in CloudWatch Logs
        log_group_prefix = f"/aws/eks/{cluster_name}/cluster"
        log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
        
        print("[+] Collecting control plane logs...")
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
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
                
                # Get events from recent streams
                for stream in streams_response.get("logStreams", [])[:5]:
                    stream_name = stream.get("logStreamName")
                    try:
                        events_response = logs_client.filter_log_events(
                            logGroupName=log_group_name,
                            logStreamNames=[stream_name],
                            startTime=int(start_time.timestamp() * 1000),
                            endTime=int(end_time.timestamp() * 1000),
                            limit=100
                        )
                        
                        stream_info = {
                            "LogStreamName": stream_name,
                            "LastEventTime": str(stream.get("lastEventTime", "")),
                            "EventCount": len(events_response.get("events", [])),
                        }
                        log_group_info["Streams"].append(stream_info)
                        log_group_info["Events"].extend(events_response.get("events", []))
                    except ClientError as e:
                        print(f"      ⚠ Error getting events: {e}")
                
                if log_group_info["Streams"]:
                    logs_data["log_groups"].append(log_group_info)
                    print(f"    ✓ Found {len(log_group_info['Events'])} event(s)")
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

