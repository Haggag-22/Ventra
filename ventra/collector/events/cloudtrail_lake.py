import json
import os
import time
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

from ventra.auth.store import get_active_profile


def _get_cloudtrail_lake_client():
    """Return CloudTrail Lake client using Ventra credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=creds["region"],
    )
    return session.client("cloudtrail")


def _start_query(ct_client, query_statement):
    """Start a CloudTrail Lake query and return query ID."""
    response = ct_client.start_query(QueryStatement=query_statement)
    return response["QueryId"]


def _wait_for_query(ct_client, query_id, poll_interval=5, timeout_minutes=10):
    """Poll query status until completion or timeout."""
    timeout_seconds = timeout_minutes * 60
    waited = 0

    while waited <= timeout_seconds:
        response = ct_client.get_query_results(QueryId=query_id)
        status = response["QueryStatus"]

        if status in ("FINISHED", "FAILED", "CANCELLED", "TIMED_OUT"):
            return status

        time.sleep(poll_interval)
        waited += poll_interval

    return "TIMED_OUT"


def _fetch_all_results(ct_client, query_id):
    """Fetch all results for a completed query."""
    results = []
    next_token = None

    while True:
        params = {"QueryId": query_id, "MaxQueryResults": 1000}
        if next_token:
            params["NextToken"] = next_token

        response = ct_client.get_query_results(**params)
        rows = response.get("QueryResultRows", [])

        for row in rows:
            record = {}

            if isinstance(row, dict):
                cells = row.get("Value", []) or row.get("Fields", []) or row.get("Values", [])
            else:
                cells = row

            for cell in cells or []:
                if not isinstance(cell, dict):
                    continue
                field = cell.get("Field")
                value = cell.get("Value")
                if field:
                    record[field] = value

            # Fallback: if record empty, store raw row
            results.append(record if record else row)

        next_token = response.get("NextToken")
        if not next_token:
            break

    return results


def _generate_output_path(args):
    """Determine output file path inside the case directory."""
    output_base = args.case_dir if hasattr(args, "case_dir") and args.case_dir else args.output
    if not output_base:
        output_base = "/Users/omar/Desktop/Ventra/output"

    output_base = os.path.join(output_base, "events")
    os.makedirs(output_base, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"cloudtrail_lake_{timestamp}.json"

    return os.path.join(output_base, filename)


def run_cloudtrail_lake(args):
    """Execute a CloudTrail Lake query and save results to the case directory."""
    print("[+] CloudTrail Lake Collector")
    print(f"    Case        : {args.case_name}")
    print(f"    Query       : {args.sql}")
    print("    Tip         : Queries poll for 10 minutes with 5s intervals. Large datasets may require longer or a future --wait option.")
    print("    Tip         : Watch for ❌ messages; CloudTrail Lake surfaces SQL/data store errors there.")

    try:
        ct_client = _get_cloudtrail_lake_client()
    except Exception as exc:
        print(f"❌ Unable to create CloudTrail Lake client: {exc}")
        return

    # Start query
    try:
        query_id = _start_query(ct_client, args.sql)
        print(f"[+] Started query ID: {query_id}")
    except ClientError as exc:
        print(f"❌ Failed to start query: {exc}")
        return

    # Wait for completion
    status = _wait_for_query(ct_client, query_id)
    print(f"[+] Query status: {status}")

    if status != "FINISHED":
        print("❌ Query did not finish successfully.")
        return

    # Fetch all results
    try:
        results = _fetch_all_results(ct_client, query_id)
    except ClientError as exc:
        print(f"❌ Failed to fetch query results: {exc}")
        return

    print(f"[+] Retrieved {len(results)} rows from CloudTrail Lake")

    # Save results
    output_path = _generate_output_path(args)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)

    print(f"[✓] Saved CloudTrail Lake results → {output_path}\n")

