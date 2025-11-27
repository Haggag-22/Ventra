import os
import json
import gzip
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_s3_client():
    """
    S3 client using Ventra's internal credentials.
    """
    profile_name, creds = get_active_profile()

    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=creds["region"],
    )
    return session.client("s3")


def _normalize_prefix(prefix):
    """
    Normalize S3 prefix path.
    If prefix is provided, use it as-is (ensure trailing slash).
    If prefix is None, return empty string to search from root.
    """
    if prefix:
        # Remove trailing slash and add it back to ensure consistency
        return prefix.rstrip('/') + '/'
    else:
        return ''  # Search from root


def _prefix_to_filename(prefix):
    """
    Convert S3 prefix path to a safe filename.
    Example: AWSLogs/525426937582/CloudTrail/us-east-1/2025/11/23
    -> cloudtrail_s3_AWSLogs_525426937582_CloudTrail_us-east-1_2025_11_23.json
    """
    if prefix:
        # Remove trailing slash and replace slashes with underscores
        safe_name = prefix.rstrip('/').replace('/', '_')
        return f"cloudtrail_s3_{safe_name}.json"
    else:
        return "cloudtrail_s3_all.json"


def _parse_cloudtrail_log(content):
    """
    Parse a CloudTrail log file (gzipped JSON).
    Returns list of events.
    """
    try:
        # Decompress gzip
        decompressed = gzip.decompress(content)
        # Parse JSON
        log_data = json.loads(decompressed.decode('utf-8'))
        # Extract records
        return log_data.get('Records', [])
    except Exception as e:
        raise Exception(f"Parse error: {e}")


def _download_and_parse(s3_client, bucket, key):
    """
    Download and parse a single S3 object in parallel.
    Returns: (events_list, error_message) or (None, error) on failure
    """
    try:
        # Download object (streaming)
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read()
        
        # Parse CloudTrail log
        events = _parse_cloudtrail_log(content)
        return events, None
    except ClientError as e:
        return None, f"Error downloading {key}: {e}"
    except Exception as e:
        return None, f"Error processing {key}: {e}"


def run_cloudtrail_s3(args):
    """
    Collect CloudTrail logs from S3 bucket using parallel downloads.
    Downloads and parses gzipped JSON log files concurrently for speed.
    """
    print("[+] CloudTrail S3 Collector (Parallel Mode)")
    print(f"    Bucket:     {args.bucket}")
    prefix = getattr(args, "prefix", None)
    if prefix:
        print(f"    Prefix:     {prefix}")
    else:
        print(f"    Prefix:     (auto-discovering from bucket root)")
    print(f"    Region:     {args.region}")

    # Normalize prefix path
    s3_prefix = _normalize_prefix(prefix)
    
    if s3_prefix:
        print(f"[+] Searching S3: s3://{args.bucket}/{s3_prefix}")
    else:
        print(f"[+] Searching S3: s3://{args.bucket}/ (all .json.gz files)")

    # Get S3 client
    try:
        s3 = _get_s3_client()
    except Exception as e:
        print(f"❌ Error getting S3 client: {e}")
        return
    
    # Step 1: Collect all object keys first (fast listing)
    print("[+] Listing S3 objects...")
    object_keys = []

    try:
        paginator = s3.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=args.bucket, Prefix=s3_prefix)
        
        for page in pages:
            if 'Contents' not in page:
                continue
            
            for obj in page['Contents']:
                key = obj['Key']
                # Only process .json.gz files
                if key.endswith('.json.gz'):
                    object_keys.append(key)
    
    except ClientError as e:
        print(f"❌ Error accessing S3 bucket: {e}")
        return
    except Exception as e:
        print(f"❌ Error: {e}")
        return

    total_files = len(object_keys)
    if total_files == 0:
        print("[!] No CloudTrail log files found.")
        return

    print(f"[+] Found {total_files} log files to process")
    print(f"[+] Starting parallel download and processing...")
    
    # Step 2: Process files in parallel
    all_events = []
    events_lock = Lock()
    processed_count = 0
    error_count = 0
    
    # Use ThreadPoolExecutor for parallel downloads
    # Default to 10 workers, can be adjusted based on needs
    max_workers = min(20, total_files)  # Cap at 20 workers
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all download tasks
        future_to_key = {
            executor.submit(_download_and_parse, s3, args.bucket, key): key
            for key in object_keys
            }

        # Process completed downloads as they finish
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            processed_count += 1
            
            try:
                events, error = future.result()
                
                if error:
                    error_count += 1
                    print(f"[!] {os.path.basename(key)}: {error}")
                elif events:
                    with events_lock:
                        all_events.extend(events)
                    
                    # Progress update every 10 files or on last file
                    if processed_count % 10 == 0 or processed_count == total_files:
                        print(f"[+] Progress: {processed_count}/{total_files} files processed, {len(all_events)} events collected")
                else:
                    print(f"[!] {os.path.basename(key)}: No events found")
            
            except Exception as e:
                error_count += 1
                print(f"[!] {os.path.basename(key)}: Unexpected error: {e}")
    
    print(f"[+] Processing complete: {processed_count} files, {error_count} errors")
    print(f"[+] Collected {len(all_events)} total CloudTrail events")
    
    if len(all_events) == 0:
        print("[!] No events found. Check bucket, prefix, and filters.")
        return
    
    # Step 3: Save all events to file
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    else:
        output_dir = args.output or "/Users/omar/Desktop/Ventra/output"
    
    # Save directly in case directory (no subdirectories)
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename based on prefix path
    prefix = getattr(args, "prefix", None)
    filename = _prefix_to_filename(prefix)
    out_file = os.path.join(output_dir, filename)
    
    print(f"[+] Saving {len(all_events)} events to file...")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_events, f, indent=2)
    
    print(f"[✓] Saved RAW CloudTrail S3 events → {out_file}\n")
