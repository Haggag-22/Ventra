import boto3
import json
import os
from datetime import datetime, timedelta, timezone
from ventra.auth.store import get_active_profile

#### Gets Logs from Cloudtail dashboard
def _get_cloudtrail_client():
    """
    CloudTrail client using Ventra's internal credentials.
    """
    profile_name, creds = get_active_profile()

    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=creds["region"],
    )
    return session.client("cloudtrail")

def run_cloudtrail_history(args):
    """
    Phase 1 Collector:
    Collect raw CloudTrail LookupEvents (API) in a SINGLE JSON file.
    No timeline. No CSV. No transformation. Test
    """

    print("[+] CloudTrail History Collector (RAW Mode)")
    print(f"    Region:     {args.region}")
    hours = getattr(args, "hours", None)
    if hours is None:
        print("    Hours Back: (ALL AVAILABLE - CloudTrail API is service-limited, typically ~90 days)")
    else:
        print(f"    Hours Back: {hours}")

    end_time = datetime.now(timezone.utc)
    start_time = None if hours is None else (end_time - timedelta(hours=hours))

    # Client
    ct = _get_cloudtrail_client()

    print("[+] Fetching CloudTrail LookupEvents...")

    paginator = ct.get_paginator("lookup_events")
    paginate_kwargs = {
        "EndTime": end_time,
        "PaginationConfig": {"PageSize": 50},
    }
    if start_time is not None:
        paginate_kwargs["StartTime"] = start_time

    pages = paginator.paginate(**paginate_kwargs)

    raw_events = []

    for page in pages:
        for wrapper_event in page.get("Events", []):
            raw_json = wrapper_event.get("CloudTrailEvent")

            if not raw_json:
                continue

            try:
                parsed = json.loads(raw_json)
                raw_events.append(parsed)
            except Exception:
                raw_events.append({"_raw": raw_json})

    print(f"[+] Collected {len(raw_events)} raw CloudTrail events")

    # Output directory - use case directory if available, otherwise fallback
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    else:
        output_dir = args.output or os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    # Save directly in case directory (no subdirectories)
    output_dir = os.path.join(output_dir, "logs")
    os.makedirs(output_dir, exist_ok=True)

    # Single raw file
    out_file = os.path.join(output_dir, "cloudtrail_history_raw.json")

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(raw_events, f, indent=2)

    print(f"[✓] Saved RAW CloudTrail events → {out_file}\n")
