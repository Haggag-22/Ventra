import boto3
import json
import os
from datetime import datetime, timedelta, timezone


def _get_cloudtrail_client(args):
    """
    CloudTrail client automatically respects environment variables,
    AWS profiles, or temp creds set by Ventra's auth module.
    """
    session = boto3.Session()
    return session.client("cloudtrail", region_name=args.region)


def run_cloudtrail_history(args):
    """
    Phase 1 Collector:
    Collect raw CloudTrail LookupEvents (API) in a SINGLE JSON file.
    No timeline. No CSV. No transformation.
    """

    print("[+] CloudTrail History Collector (RAW Mode)")
    print(f"    Region:     {args.region}")
    print(f"    Hours Back: {args.hours}")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=args.hours)

    # Client
    ct = _get_cloudtrail_client(args)

    print("[+] Fetching CloudTrail LookupEvents...")

    paginator = ct.get_paginator("lookup_events")
    pages = paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"PageSize": 50}
    )

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

    # Output directory
    out_dir = os.path.join(args.output, "cloudtrail", "history")
    os.makedirs(out_dir, exist_ok=True)

    # Single raw file
    out_file = os.path.join(out_dir, "cloudtrail_history_raw.json")

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(raw_events, f, indent=2)

    print(f"[✓] Saved RAW CloudTrail events → {out_file}\n")
