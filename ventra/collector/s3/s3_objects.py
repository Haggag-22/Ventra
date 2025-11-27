"""
S3 Objects Collector
Lightweight listing of objects (NOT downloading everything).
Recursively lists all objects under a given prefix.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_s3_client(region):
    """S3 client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("s3")


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


def run_s3_objects(args):
    """Collect S3 object listing."""
    bucket_name = args.bucket
    prefix = getattr(args, "prefix", "")
    limit = getattr(args, "limit", None)
    
    print(f"[+] S3 Objects Collector")
    print(f"    Bucket:      {bucket_name}")
    print(f"    Prefix:     {prefix if prefix else '(root)'}")
    if limit:
        print(f"    Limit:       {limit} objects")
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
        s3_client = _get_s3_client(args.region)
    except Exception as e:
        print(f"❌ Error getting S3 client: {e}")
        return
    
    try:
        objects_data = {
            "bucket": bucket_name,
            "prefix": prefix,
            "objects": [],
            "common_prefixes": [],
        }
        
        print("[+] Listing objects (recursively)...")
        object_count = 0
        
        paginator = s3_client.get_paginator("list_objects_v2")
        page_iterator = paginator.paginate(
            Bucket=bucket_name,
            Prefix=prefix if prefix else "",
            Delimiter=""  # No delimiter = recursive listing
        )
        
        for page in page_iterator:
            # Process objects
            for obj in page.get("Contents", []):
                if limit and object_count >= limit:
                    print(f"    ⚠ Reached limit of {limit} objects")
                    break
                
                obj_info = {
                    "Key": obj.get("Key"),
                    "Size": obj.get("Size"),
                    "LastModified": str(obj.get("LastModified", "")),
                    "ETag": obj.get("ETag", "").strip('"'),
                    "StorageClass": obj.get("StorageClass"),
                    "Owner": obj.get("Owner", {}),
                }
                objects_data["objects"].append(obj_info)
                object_count += 1
                
                if object_count % 1000 == 0:
                    print(f"    ... Listed {object_count} objects so far...")
            
            if limit and object_count >= limit:
                break
            
            # Process common prefixes (folders)
            for prefix_item in page.get("CommonPrefixes", []):
                objects_data["common_prefixes"].append(prefix_item.get("Prefix"))
        
        objects_data["total_objects"] = len(objects_data["objects"])
        objects_data["total_prefixes"] = len(objects_data["common_prefixes"])
        
        print(f"    ✓ Listed {objects_data['total_objects']} object(s)")
        if objects_data["total_prefixes"] > 0:
            print(f"    ✓ Found {objects_data['total_prefixes']} prefix(es)")
        
        # Save single combined file
        safe_prefix = prefix.replace("/", "_").replace(" ", "_") if prefix else "root"
        filename = f"s3_objects_{bucket_name}_{safe_prefix}.json"
        filepath = _save_json_file(output_dir, filename, objects_data)
        if filepath:
            print(f"\n[✓] Saved object listing → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

