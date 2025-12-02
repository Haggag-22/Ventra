"""
S3 Versions Collector
If bucket has versioning enabled, lists all versions and delete-markers.
Extremely valuable in breach investigations.
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


def run_s3_versions(args):
    """Collect S3 object versions and delete markers."""
    bucket_name = args.bucket
    prefix = getattr(args, "prefix", "")
    
    print(f"[+] S3 Versions Collector")
    print(f"    Bucket:      {bucket_name}")
    print(f"    Prefix:     {prefix if prefix else '(all objects)'}")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "resources")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        s3_client = _get_s3_client(args.region)
    except Exception as e:
        print(f"❌ Error getting S3 client: {e}")
        return
    
    try:
        # Check if versioning is enabled
        print("[+] Checking versioning status...")
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_status = versioning.get("Status", "NotEnabled")
            if versioning_status != "Enabled":
                print(f"    ⚠ Versioning is not enabled (Status: {versioning_status})")
                print(f"    ⚠ No versions to collect")
                versions_data = {
                    "bucket": bucket_name,
                    "versioning_status": versioning_status,
                    "versions": [],
                    "delete_markers": [],
                    "message": "Versioning is not enabled for this bucket"
                }
                filename = f"s3_versions_{bucket_name}.json"
                filepath = _save_json_file(output_dir, filename, versions_data)
                if filepath:
                    print(f"\n[✓] Saved version info → {filepath}\n")
                return
            else:
                print(f"    ✓ Versioning is enabled")
        except ClientError as e:
            print(f"    ⚠ Error checking versioning: {e}")
            return
        
        versions_data = {
            "bucket": bucket_name,
            "prefix": prefix,
            "versions": [],
            "delete_markers": [],
        }
        
        print("[+] Listing all object versions...")
        version_count = 0
        delete_marker_count = 0
        
        paginator = s3_client.get_paginator("list_object_versions")
        page_iterator = paginator.paginate(
            Bucket=bucket_name,
            Prefix=prefix if prefix else "",
        )
        
        for page in page_iterator:
            # Process versions
            for version in page.get("Versions", []):
                version_info = {
                    "Key": version.get("Key"),
                    "VersionId": version.get("VersionId"),
                    "IsLatest": version.get("IsLatest"),
                    "LastModified": str(version.get("LastModified", "")),
                    "ETag": version.get("ETag", "").strip('"'),
                    "Size": version.get("Size"),
                    "StorageClass": version.get("StorageClass"),
                    "Owner": version.get("Owner", {}),
                }
                versions_data["versions"].append(version_info)
                version_count += 1
                
                if version_count % 1000 == 0:
                    print(f"    ... Listed {version_count} versions so far...")
            
            # Process delete markers
            for delete_marker in page.get("DeleteMarkers", []):
                marker_info = {
                    "Key": delete_marker.get("Key"),
                    "VersionId": delete_marker.get("VersionId"),
                    "IsLatest": delete_marker.get("IsLatest"),
                    "LastModified": str(delete_marker.get("LastModified", "")),
                    "Owner": delete_marker.get("Owner", {}),
                }
                versions_data["delete_markers"].append(marker_info)
                delete_marker_count += 1
        
        versions_data["total_versions"] = len(versions_data["versions"])
        versions_data["total_delete_markers"] = len(versions_data["delete_markers"])
        
        print(f"    ✓ Listed {versions_data['total_versions']} version(s)")
        print(f"    ✓ Found {versions_data['total_delete_markers']} delete marker(s)")
        
        if delete_marker_count > 0:
            print(f"    ⚠ Found delete markers - potential evidence of data deletion!")
        
        # Save single combined file
        safe_prefix = prefix.replace("/", "_").replace(" ", "_") if prefix else "all"
        filename = f"s3_versions_{bucket_name}_{safe_prefix}.json"
        filepath = _save_json_file(output_dir, filename, versions_data)
        if filepath:
            print(f"\n[✓] Saved version listing → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

