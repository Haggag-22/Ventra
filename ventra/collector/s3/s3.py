"""
S3 Collector Module
Collects comprehensive S3 bucket information.
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


def collect_bucket_list(s3_client):
    """Collect list of all buckets."""
    buckets = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get("Buckets", []):
            buckets.append({
                "Name": bucket.get("Name"),
                "CreationDate": str(bucket.get("CreationDate", "")),
            })
    except ClientError as e:
        print(f"    ❌ Error listing buckets: {e}")
    return buckets


def collect_bucket_details(s3_client, bucket_name, include_objects=False):
    """Collect detailed information for a single bucket."""
    bucket_data = {
        "BucketName": bucket_name,
        "Location": None,
        "Policy": None,
        "ACL": None,
        "Encryption": None,
        "Versioning": None,
        "Lifecycle": None,
        "PublicAccessBlock": None,
        "Logging": None,
        "Website": None,
        "CORS": None,
        "Notification": None,
        "Replication": None,
        "RequestPayment": None,
        "Tagging": None,
        "Objects": [] if include_objects else None,
    }
    
    try:
        # Get bucket location
        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_data["Location"] = location.get("LocationConstraint") or "us-east-1"
        except ClientError:
            pass
        
        # Get bucket policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            bucket_data["Policy"] = json.loads(policy.get("Policy", "{}"))
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "NoSuchBucketPolicy":
                print(f"      ⚠ Error getting bucket policy: {e}")
        
        # Get bucket ACL
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            bucket_data["ACL"] = {
                "Owner": acl.get("Owner", {}),
                "Grants": acl.get("Grants", []),
            }
        except ClientError as e:
            print(f"      ⚠ Error getting bucket ACL: {e}")
        
        # Get encryption configuration
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            bucket_data["Encryption"] = encryption.get("ServerSideEncryptionConfiguration", {})
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"]:
                print(f"      ⚠ Error getting encryption: {e}")
        
        # Get versioning configuration
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            bucket_data["Versioning"] = {
                "Status": versioning.get("Status"),
                "MfaDelete": versioning.get("MfaDelete"),
            }
        except ClientError as e:
            print(f"      ⚠ Error getting versioning: {e}")
        
        # Get lifecycle configuration
        try:
            lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            bucket_data["Lifecycle"] = lifecycle.get("Rules", [])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["NoSuchLifecycleConfiguration", "NoSuchBucket"]:
                print(f"      ⚠ Error getting lifecycle: {e}")
        
        # Get public access block
        try:
            pab = s3_client.get_public_access_block(Bucket=bucket_name)
            bucket_data["PublicAccessBlock"] = pab.get("PublicAccessBlockConfiguration", {})
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"]:
                print(f"      ⚠ Error getting public access block: {e}")
        
        # Get bucket logging
        try:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            bucket_data["Logging"] = logging.get("LoggingEnabled", {})
        except ClientError as e:
            print(f"      ⚠ Error getting logging: {e}")
        
        # Get website configuration
        try:
            website = s3_client.get_bucket_website(Bucket=bucket_name)
            bucket_data["Website"] = website
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["NoSuchWebsiteConfiguration", "NoSuchBucket"]:
                print(f"      ⚠ Error getting website config: {e}")
        
        # Get CORS configuration
        try:
            cors = s3_client.get_bucket_cors(Bucket=bucket_name)
            bucket_data["CORS"] = cors.get("CORSRules", [])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["NoSuchCORSConfiguration", "NoSuchBucket"]:
                print(f"      ⚠ Error getting CORS: {e}")
        
        # Get notification configuration
        try:
            notification = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            bucket_data["Notification"] = {
                "TopicConfigurations": notification.get("TopicConfigurations", []),
                "QueueConfigurations": notification.get("QueueConfigurations", []),
                "LambdaFunctionConfigurations": notification.get("LambdaFunctionConfigurations", []),
                "EventBridgeConfiguration": notification.get("EventBridgeConfiguration", {}),
            }
        except ClientError as e:
            print(f"      ⚠ Error getting notification config: {e}")
        
        # Get replication configuration
        try:
            replication = s3_client.get_bucket_replication(Bucket=bucket_name)
            bucket_data["Replication"] = replication.get("ReplicationConfiguration", {})
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["ReplicationConfigurationNotFoundError", "NoSuchBucket"]:
                print(f"      ⚠ Error getting replication: {e}")
        
        # Get request payment configuration
        try:
            request_payment = s3_client.get_bucket_request_payment(Bucket=bucket_name)
            bucket_data["RequestPayment"] = request_payment.get("Payer", "")
        except ClientError as e:
            print(f"      ⚠ Error getting request payment: {e}")
        
        # Get bucket tagging
        try:
            tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
            bucket_data["Tagging"] = {tag.get("Key"): tag.get("Value") for tag in tagging.get("TagSet", [])}
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["NoSuchTagSet", "NoSuchBucket"]:
                print(f"      ⚠ Error getting tagging: {e}")
        
        # Optionally list objects
        if include_objects:
            try:
                print(f"      [+] Listing objects (this may take a while for large buckets)...")
                objects = []
                paginator = s3_client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket_name):
                    for obj in page.get("Contents", []):
                        objects.append({
                            "Key": obj.get("Key"),
                            "LastModified": str(obj.get("LastModified", "")),
                            "ETag": obj.get("ETag"),
                            "Size": obj.get("Size"),
                            "StorageClass": obj.get("StorageClass"),
                        })
                bucket_data["Objects"] = objects
                bucket_data["ObjectCount"] = len(objects)
                print(f"        ✓ Found {len(objects)} object(s)")
            except ClientError as e:
                print(f"      ⚠ Error listing objects: {e}")
        
    except ClientError as e:
        print(f"    ❌ Error accessing bucket {bucket_name}: {e}")
    
    return bucket_data


def run_s3_bucket(args):
    """Collect detailed information for a specific bucket."""
    bucket_name = args.name
    include_objects = getattr(args, "objects", False)
    
    print(f"[+] S3 Bucket Collector")
    print(f"    Bucket:      {bucket_name}")
    print(f"    Include Objects: {include_objects}")
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
        print(f"[+] Collecting bucket details...")
        bucket_data = collect_bucket_details(s3_client, bucket_name, include_objects)
        
        # Save single combined file
        filename = f"s3_{bucket_name}.json"
        filepath = _save_json_file(output_dir, filename, bucket_data)
        if filepath:
            print(f"\n[✓] Saved bucket data → {filepath}\n")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def run_s3_all(args):
    """Collect information for all buckets."""
    include_objects = getattr(args, "objects", False)
    
    print(f"[+] S3 All Buckets Collector")
    print(f"    Include Objects: {include_objects}")
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
        print(f"[+] Listing all buckets...")
        buckets = collect_bucket_list(s3_client)
        print(f"    ✓ Found {len(buckets)} bucket(s)\n")
        
        all_buckets_data = {
            "BucketCount": len(buckets),
            "Buckets": [],
        }
        
        for idx, bucket_info in enumerate(buckets, 1):
            bucket_name = bucket_info.get("Name")
            print(f"[{idx}/{len(buckets)}] Processing bucket: {bucket_name}")
            bucket_data = collect_bucket_details(s3_client, bucket_name, include_objects)
            all_buckets_data["Buckets"].append(bucket_data)
        
        # Save single combined file
        filename = "s3_all_buckets.json"
        filepath = _save_json_file(output_dir, filename, all_buckets_data)
        if filepath:
            print(f"\n[✓] Saved all buckets data → {filepath}\n")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

