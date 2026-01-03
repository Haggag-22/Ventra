"""
VPC Flow Logs Collector (Logs Domain)
Collects VPC flow log configuration and optionally recent flow log events from:
- CloudWatch Logs (LogDestinationType: cloud-watch-logs)
- S3 (LogDestinationType: s3)
"""
import os
import json
import re
import boto3
import gzip
from typing import Optional, List, Dict, Any
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


def _get_s3_client(region):
    """S3 client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("s3")


def _get_sts_client(region):
    """STS client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("sts")


def _get_account_id(region: str) -> Optional[str]:
    try:
        sts = _get_sts_client(region)
        return sts.get_caller_identity().get("Account")
    except Exception:
        return None


def _candidate_flowlogs_prefixes(
    account_id: Optional[str],
    region: Optional[str],
    explicit_prefix: Optional[str],
) -> List[str]:
    """
    When a Flow Logs S3 destination is only a bucket (no prefix), AWS usually writes to:
      AWSLogs/<account-id>/vpcflowlogs/<region>/YYYY/MM/DD/...
    We'll try a few common prefixes to avoid scanning the entire bucket.
    """
    prefixes: List[str] = []
    if explicit_prefix:
        prefixes.append(explicit_prefix.strip("/"))

    if account_id and region:
        prefixes.append(f"AWSLogs/{account_id}/vpcflowlogs/{region}")
    if account_id:
        prefixes.append(f"AWSLogs/{account_id}/vpcflowlogs")

    # De-dup while preserving order
    out: List[str] = []
    for p in prefixes:
        p = (p or "").strip("/")
        if p and p not in out:
            out.append(p)
    return out


def _infer_destination_type(flow_log: dict) -> str:
    """Infer destination type from flow log record."""
    t = (flow_log.get("LogDestinationType") or "").strip().lower()
    if t:
        return t

    dest = (flow_log.get("LogDestination") or "").strip()
    if "log-group:" in dest:
        return "cloud-watch-logs"
    if dest.startswith("arn:aws:s3:::") or dest.startswith("s3://"):
        return "s3"
    return "unknown"


def _parse_s3_destination(dest: str):
    """
    Parse S3 destination into (bucket, prefix).
    Accepts:
      - arn:aws:s3:::bucket
      - arn:aws:s3:::bucket/prefix
      - s3://bucket/prefix
      - bucket/prefix (best-effort)
    """
    if not dest:
        return None, None

    s = dest.strip()
    if s.startswith("arn:aws:s3:::"):
        s = s[len("arn:aws:s3:::"):]
    elif s.startswith("s3://"):
        s = s[len("s3://"):]

    if "/" in s:
        bucket, prefix = s.split("/", 1)
        prefix = prefix.strip("/")
    else:
        bucket, prefix = s, ""

    bucket = bucket.strip()
    return bucket or None, prefix or ""


def _parse_flow_log_line(line: str) -> dict:
    """
    Best-effort parse of default VPC Flow Logs format (version 2 default fields).
    If the format doesn't match, returns {'raw': line}.
    """
    line = line.strip()
    if not line:
        return {}
    # Some deliveries may include header lines; ignore known headers
    if line.lower().startswith("version ") or line.lower().startswith("account-id "):
        return {}

    parts = line.split()
    if len(parts) < 14:
        return {"raw": line}

    return {
        "version": parts[0],
        "account_id": parts[1],
        "interface_id": parts[2],
        "srcaddr": parts[3],
        "dstaddr": parts[4],
        "srcport": parts[5],
        "dstport": parts[6],
        "protocol": parts[7],
        "packets": parts[8],
        "bytes": parts[9],
        "start": parts[10],
        "end": parts[11],
        "action": parts[12],
        "log_status": parts[13],
        # Preserve any additional custom fields
        "extra": parts[14:] if len(parts) > 14 else [],
    }


def _resolve_output_dir(args):
    """Resolve output directory - use case_dir if available, otherwise fallback."""
    if hasattr(args, "case_dir") and args.case_dir:
        output_base = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_base = args.output
    else:
        output_base = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_base = os.path.join(output_base, "logs")
    os.makedirs(output_base, exist_ok=True)
    return output_base


def run_vpc_flow_logs(args):
    """Collect VPC flow log configuration and optionally recent log events."""
    print("[+] VPC Flow Logs Collector (Logs)")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
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

        # If hours is omitted, collect all available history (may be large).
        # hours == 0 also means "all".
        collect_all = (hours is None) or (hours == 0)
        
        if collect_all:
            print("[+] Collecting flow log events (all available history)...")
        else:
            print(f"[+] Collecting flow log events from last {hours} hours...")

        # Lazily initialize clients
        logs_client = None
        s3_client = None
        account_id = None

        collected: List[Dict[str, Any]] = []

        for flow_log in flow_logs:
            dest_type = _infer_destination_type(flow_log)
            log_destination = (flow_log.get("LogDestination") or "").strip()

            if not log_destination:
                continue

            # -----------------------------------------------------------------
            # CloudWatch Logs destination
            # -----------------------------------------------------------------
            if dest_type == "cloud-watch-logs":
                # Extract log group name from ARN
                # Format: arn:aws:logs:region:account:log-group:/aws/vpc/flowlogs
                log_group_match = re.search(r"log-group:(.+?)(?::|$)", log_destination)
                if not log_group_match:
                    continue

                log_group_name = log_group_match.group(1)
                print(f"    Collecting from CloudWatch log group: {log_group_name}")

                if logs_client is None:
                    try:
                        logs_client = _get_cloudwatch_logs_client(args.region)
                    except Exception as e:
                        print(f"      ⚠ Error creating CloudWatch Logs client: {e}")
                        continue

                end_time = datetime.now(timezone.utc)
                if collect_all:
                    start_timestamp = 0
                else:
                    start_time = end_time - timedelta(hours=hours)
                    start_timestamp = int(start_time.timestamp() * 1000)
                end_timestamp = int(end_time.timestamp() * 1000)

                events: List[Dict[str, Any]] = []
                try:
                    paginator = logs_client.get_paginator("filter_log_events")
                    for page in paginator.paginate(
                        logGroupName=log_group_name,
                        startTime=start_timestamp,
                        endTime=end_timestamp,
                    ):
                        for event in page.get("events", []):
                            events.append(
                                {
                                    "timestamp": event.get("timestamp"),
                                    "message": event.get("message"),
                                    "logStreamName": event.get("logStreamName"),
                                }
                            )

                    collected.append(
                        {
                            "destination": "cloudwatch",
                            "flow_log_id": flow_log.get("FlowLogId"),
                            "resource_id": flow_log.get("ResourceId"),
                            "log_destination_type": dest_type,
                            "log_destination": log_destination,
                            "log_group": log_group_name,
                            "hours": None if collect_all else hours,
                            "events_total": len(events),
                            "events": events,
                        }
                    )
                    print(f"      ✓ Collected {len(events)} event(s)")
                except Exception as e:
                    print(f"      ⚠ Error collecting CloudWatch events: {e}")

            # -----------------------------------------------------------------
            # S3 destination
            # -----------------------------------------------------------------
            elif dest_type == "s3":
                bucket, prefix = _parse_s3_destination(log_destination)
                if not bucket:
                    print(f"      ⚠ Could not parse S3 destination: {log_destination}")
                    continue

                if account_id is None:
                    account_id = _get_account_id(args.region)

                if s3_client is None:
                    try:
                        s3_client = _get_s3_client(args.region)
                    except Exception as e:
                        print(f"      ⚠ Error creating S3 client: {e}")
                        continue

                end_time = datetime.now(timezone.utc)
                start_time = None if collect_all else (end_time - timedelta(hours=hours))

                # Safety caps to avoid runaway downloads
                max_objects = 500 if collect_all else 200
                max_records_total = 200_000

                objects: List[Dict[str, Any]] = []
                chosen_prefix = prefix or ""
                try:
                    paginator = s3_client.get_paginator("list_objects_v2")
                    prefixes_to_try = _candidate_flowlogs_prefixes(account_id, getattr(args, "region", None), prefix)
                    if not prefixes_to_try:
                        prefixes_to_try = [""]

                    for pfx in prefixes_to_try:
                        objects.clear()
                        list_prefix = (pfx + "/") if pfx else ""
                        print(f"    Collecting from S3: s3://{bucket}/{pfx}" if pfx else f"    Collecting from S3: s3://{bucket}/")

                        for page in paginator.paginate(Bucket=bucket, Prefix=list_prefix):
                            for obj in page.get("Contents", []):
                                lm = obj.get("LastModified")
                                key = obj.get("Key")
                                if not key or not lm:
                                    continue
                                if start_time is not None:
                                    lm_utc = lm.astimezone(timezone.utc) if getattr(lm, "tzinfo", None) else lm.replace(tzinfo=timezone.utc)
                                    if lm_utc < start_time:
                                        continue
                                objects.append(
                                    {
                                        "key": key,
                                        "last_modified": lm.isoformat(),
                                        "size": obj.get("Size"),
                                    }
                                )

                        if objects:
                            chosen_prefix = pfx
                            break
                except Exception as e:
                    print(f"      ⚠ Error listing S3 objects: {e}")
                    continue

                # Sort newest-first and cap
                objects.sort(key=lambda o: o.get("last_modified", ""), reverse=True)
                objects_to_fetch = objects[:max_objects]
                objects_truncated = len(objects) > len(objects_to_fetch)

                records: List[Dict[str, Any]] = []
                truncated = False
                fetched = 0
                try:
                    for o in objects_to_fetch:
                        key = o["key"]
                        try:
                            resp = s3_client.get_object(Bucket=bucket, Key=key)
                            body = resp["Body"].read()
                            if key.endswith(".gz"):
                                body = gzip.decompress(body)
                            text = body.decode("utf-8", errors="replace")
                        except Exception as e:
                            print(f"      ⚠ Error downloading {key}: {e}")
                            continue

                        fetched += 1
                        for line in text.splitlines():
                            rec = _parse_flow_log_line(line)
                            if not rec:
                                continue
                            records.append(rec)
                            if len(records) >= max_records_total:
                                truncated = True
                                break
                        if truncated:
                            break
                except Exception as e:
                    print(f"      ⚠ Error processing S3 flow log objects: {e}")

                collected.append(
                    {
                        "destination": "s3",
                        "flow_log_id": flow_log.get("FlowLogId"),
                        "resource_id": flow_log.get("ResourceId"),
                        "log_destination_type": dest_type,
                        "log_destination": log_destination,
                        "bucket": bucket,
                        "prefix": chosen_prefix,
                        "hours": None if collect_all else hours,
                        "objects_matched": len(objects),
                        "objects_downloaded": fetched,
                        "objects_truncated": objects_truncated,
                        "objects": objects_to_fetch,
                        "records_total": len(records),
                        "records_truncated": truncated,
                        "records": records,
                    }
                )

                msg = f"      ✓ Collected {len(records)} record(s)"
                if objects_truncated or truncated:
                    msg += " (TRUNCATED)"
                print(msg)

            else:
                # Kinesis Data Firehose / unknown destinations are not supported yet
                print(f"    ⚠ Unsupported Flow Logs destination type: {dest_type} (LogDestination={log_destination})")
        
        # Save ONE combined output file (config + collected data)
        vpc_id = getattr(args, "vpc_id", None)
        vpc_suffix = f"_{vpc_id}" if vpc_id else "_all"
        suffix = "" if collect_all else f"_{hours}h"
        filename = f"vpc_flow_logs{vpc_suffix}{suffix}.json"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "region": args.region,
                    "hours": None if collect_all else hours,
                    "collect_all": collect_all,
                    "vpc_id": vpc_id,
                    "flow_logs": flow_logs,
                    "flow_logs_total": len(flow_logs),
                    "collected": collected,
                    "collected_total": len(collected),
                },
                f,
                indent=2,
                default=str,
            )

        # Remove legacy multi-file outputs (from older versions) to keep the
        # case directory clean and consistent (single output file per run).
        try:
            for fname in os.listdir(output_dir):
                if fname == filename:
                    continue
                if fname == "vpc_flow_logs.json":
                    os.remove(os.path.join(output_dir, fname))
                    continue
                if fname.startswith("vpc_flow_logs_s3_"):
                    os.remove(os.path.join(output_dir, fname))
                    continue
                if fname.startswith("vpc_flow_logs_") and not fname.startswith("vpc_flow_logs" + vpc_suffix):
                    os.remove(os.path.join(output_dir, fname))
        except Exception:
            # Best-effort cleanup; do not fail the collector if deletion is blocked.
            pass

        print(f"\n[✓] Saved VPC Flow Logs output → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

