"""
S3 Bucket Info Collector
Collects bucket metadata, ACL, policy, encryption, object-lock, lifecycle, replication, CORS, website config.
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


def run_s3_bucket_info(args):
    """Collect comprehensive bucket information."""
    bucket_name = args.bucket
    print(f"[+] S3 Bucket Info Collector")
    print(f"    Bucket:      {bucket_name}")
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
        bucket_data = {}
        
        # Get bucket location
        print("[+] Collecting bucket location...")
        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_data["location"] = location.get("LocationConstraint") or "us-east-1"
            print(f"    ✓ Location: {bucket_data['location']}")
        except ClientError as e:
            print(f"    ⚠ Error getting location: {e}")
            bucket_data["location"] = None
        
        # Get bucket ACL
        print("[+] Collecting bucket ACL...")
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            bucket_data["acl"] = acl
            print(f"    ✓ Collected ACL")
        except ClientError as e:
            print(f"    ⚠ Error getting ACL: {e}")
            bucket_data["acl"] = None
        
        # Get bucket policy
        print("[+] Collecting bucket policy...")
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            bucket_data["policy"] = json.loads(policy.get("Policy", "{}"))
            print(f"    ✓ Collected policy")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucketPolicy":
                bucket_data["policy"] = None
                print(f"    ⚠ No bucket policy")
            else:
                print(f"    ⚠ Error getting policy: {e}")
                bucket_data["policy"] = None
        
        # Get bucket encryption
        print("[+] Collecting encryption configuration...")
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            bucket_data["encryption"] = encryption.get("ServerSideEncryptionConfiguration", {})
            print(f"    ✓ Collected encryption config")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                bucket_data["encryption"] = None
                print(f"    ⚠ No encryption configured")
            else:
                print(f"    ⚠ Error getting encryption: {e}")
                bucket_data["encryption"] = None
        
        # Get object lock configuration
        print("[+] Collecting object lock configuration...")
        try:
            object_lock = s3_client.get_object_lock_configuration(Bucket=bucket_name)
            bucket_data["object_lock"] = object_lock.get("ObjectLockConfiguration", {})
            print(f"    ✓ Collected object lock config")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ObjectLockConfigurationNotFoundError":
                bucket_data["object_lock"] = None
                print(f"    ⚠ No object lock configured")
            else:
                print(f"    ⚠ Error getting object lock: {e}")
                bucket_data["object_lock"] = None
        
        # Get lifecycle configuration
        print("[+] Collecting lifecycle configuration...")
        try:
            lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            bucket_data["lifecycle"] = lifecycle.get("Rules", [])
            print(f"    ✓ Collected lifecycle config ({len(bucket_data['lifecycle'])} rules)")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchLifecycleConfiguration":
                bucket_data["lifecycle"] = []
                print(f"    ⚠ No lifecycle rules")
            else:
                print(f"    ⚠ Error getting lifecycle: {e}")
                bucket_data["lifecycle"] = []
        
        # Get replication configuration
        print("[+] Collecting replication configuration...")
        try:
            replication = s3_client.get_bucket_replication(Bucket=bucket_name)
            bucket_data["replication"] = replication.get("ReplicationConfiguration", {})
            print(f"    ✓ Collected replication config")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ReplicationConfigurationNotFoundError":
                bucket_data["replication"] = None
                print(f"    ⚠ No replication configured")
            else:
                print(f"    ⚠ Error getting replication: {e}")
                bucket_data["replication"] = None
        
        # Get CORS configuration
        print("[+] Collecting CORS configuration...")
        try:
            cors = s3_client.get_bucket_cors(Bucket=bucket_name)
            bucket_data["cors"] = cors.get("CORSRules", [])
            print(f"    ✓ Collected CORS config ({len(bucket_data['cors'])} rules)")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchCORSConfiguration":
                bucket_data["cors"] = []
                print(f"    ⚠ No CORS configured")
            else:
                print(f"    ⚠ Error getting CORS: {e}")
                bucket_data["cors"] = []
        
        # Get website configuration
        print("[+] Collecting website configuration...")
        try:
            website = s3_client.get_bucket_website(Bucket=bucket_name)
            bucket_data["website"] = website
            print(f"    ✓ Collected website config")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchWebsiteConfiguration":
                bucket_data["website"] = None
                print(f"    ⚠ No website configured")
            else:
                print(f"    ⚠ Error getting website: {e}")
                bucket_data["website"] = None
        
        # Get public access block
        print("[+] Collecting public access block configuration...")
        try:
            public_access = s3_client.get_public_access_block(Bucket=bucket_name)
            bucket_data["public_access_block"] = public_access.get("PublicAccessBlockConfiguration", {})
            print(f"    ✓ Collected public access block")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                bucket_data["public_access_block"] = None
                print(f"    ⚠ No public access block configured")
            else:
                print(f"    ⚠ Error getting public access block: {e}")
                bucket_data["public_access_block"] = None
        
        # Get bucket logging
        print("[+] Collecting bucket logging configuration...")
        try:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            bucket_data["logging"] = logging.get("LoggingEnabled", {})
            if bucket_data["logging"]:
                print(f"    ✓ Logging enabled")
            else:
                print(f"    ⚠ Logging not enabled")
        except ClientError as e:
            print(f"    ⚠ Error getting logging: {e}")
            bucket_data["logging"] = None
        
        # Get bucket versioning
        print("[+] Collecting versioning configuration...")
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            bucket_data["versioning"] = {
                "Status": versioning.get("Status"),
                "MfaDelete": versioning.get("MfaDelete"),
            }
            print(f"    ✓ Versioning: {bucket_data['versioning'].get('Status', 'NotEnabled')}")
        except ClientError as e:
            print(f"    ⚠ Error getting versioning: {e}")
            bucket_data["versioning"] = None
        
        # Get bucket notification configuration
        print("[+] Collecting notification configuration...")
        try:
            notifications = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            bucket_data["notifications"] = {
                "TopicConfigurations": notifications.get("TopicConfigurations", []),
                "QueueConfigurations": notifications.get("QueueConfigurations", []),
                "LambdaFunctionConfigurations": notifications.get("LambdaFunctionConfigurations", []),
                "EventBridgeConfiguration": notifications.get("EventBridgeConfiguration", {}),
            }
            print(f"    ✓ Collected notification config")
        except ClientError as e:
            print(f"    ⚠ Error getting notifications: {e}")
            bucket_data["notifications"] = {}
        
        # Get bucket tagging
        print("[+] Collecting bucket tags...")
        try:
            tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
            bucket_data["tags"] = {tag["Key"]: tag["Value"] for tag in tagging.get("TagSet", [])}
            print(f"    ✓ Collected {len(bucket_data['tags'])} tag(s)")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchTagSet":
                bucket_data["tags"] = {}
                print(f"    ⚠ No tags")
            else:
                print(f"    ⚠ Error getting tags: {e}")
                bucket_data["tags"] = {}
        
        # Save single combined file
        filename = f"s3_bucket_info_{bucket_name}.json"
        filepath = _save_json_file(output_dir, filename, bucket_data)
        if filepath:
            print(f"\n[✓] Saved bucket info → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

