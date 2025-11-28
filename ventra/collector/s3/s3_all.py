"""
S3 All Collector
Collects all S3 bucket information (bucket info, access, objects, versions) into a single combined file.
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


def _get_s3control_client(region):
    """S3 Control client for access points."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("s3control")


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


def _check_public_access(s3_client, bucket_name):
    """Check if bucket is publicly accessible."""
    public_access = {
        "is_public": False,
        "public_read": False,
        "public_write": False,
        "public_read_write": False,
    }
    
    try:
        # Check ACL for public access
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") == "Group":
                uri = grantee.get("URI", "")
                permission = grant.get("Permission", "")
                
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public_access["is_public"] = True
                    if permission in ["READ", "FULL_CONTROL"]:
                        public_access["public_read"] = True
                    if permission in ["WRITE", "FULL_CONTROL"]:
                        public_access["public_write"] = True
                    if permission == "FULL_CONTROL":
                        public_access["public_read_write"] = True
        
        # Check bucket policy for public access
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy.get("Policy", "{}"))
            policy_str = json.dumps(policy_doc)
            if '"Principal": "*"' in policy_str or '"Principal": {"AWS": "*"}' in policy_str:
                public_access["is_public"] = True
        except ClientError:
            pass
            
    except Exception as e:
        pass
    
    return public_access


def run_s3_all(args):
    """Collect all S3 bucket data into a single file."""
    bucket_name = args.bucket
    prefix = getattr(args, "prefix", "")
    limit = getattr(args, "limit", None)
    
    print(f"[+] S3 All Collector")
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
        s3control_client = _get_s3control_client(args.region)
    except Exception as e:
        print(f"❌ Error getting S3 clients: {e}")
        return
    
    try:
        all_data = {
            "BucketName": bucket_name,
            "Prefix": prefix if prefix else None,
            "BucketInfo": {},
            "Access": {},
            "Objects": {"objects": [], "common_prefixes": []},
            "Versions": {"versions": [], "delete_markers": []},
        }
        
        # 1. Collect bucket info
        print("[+] Collecting bucket information...")
        bucket_info = {}
        try:
            # Location
            try:
                location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_info["location"] = location.get("LocationConstraint") or "us-east-1"
            except Exception as e:
                print(f"    ⚠ Error getting location: {e} (continuing)")
            
            # ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                bucket_info["acl"] = acl
            except Exception as e:
                print(f"    ⚠ Error getting ACL: {e} (continuing)")
            
            # Policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                bucket_info["policy"] = json.loads(policy.get("Policy", "{}"))
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                    print(f"    ⚠ Error getting policy: {e} (continuing)")
            
            # Encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                bucket_info["encryption"] = encryption.get("ServerSideEncryptionConfiguration", {})
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ServerSideEncryptionConfigurationNotFoundError":
                    print(f"    ⚠ Error getting encryption: {e} (continuing)")
            
            # Object lock
            try:
                object_lock = s3_client.get_object_lock_configuration(Bucket=bucket_name)
                bucket_info["object_lock"] = object_lock.get("ObjectLockConfiguration", {})
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ObjectLockConfigurationNotFoundError":
                    print(f"    ⚠ Error getting object lock: {e} (continuing)")
            
            # Lifecycle
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                bucket_info["lifecycle"] = lifecycle.get("Rules", [])
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchLifecycleConfiguration":
                    print(f"    ⚠ Error getting lifecycle: {e} (continuing)")
            
            # Replication
            try:
                replication = s3_client.get_bucket_replication(Bucket=bucket_name)
                bucket_info["replication"] = replication.get("ReplicationConfiguration", {})
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ReplicationConfigurationNotFoundError":
                    print(f"    ⚠ Error getting replication: {e} (continuing)")
            
            # CORS
            try:
                cors = s3_client.get_bucket_cors(Bucket=bucket_name)
                bucket_info["cors"] = cors.get("CORSRules", [])
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchCORSConfiguration":
                    print(f"    ⚠ Error getting CORS: {e} (continuing)")
            
            # Website
            try:
                website = s3_client.get_bucket_website(Bucket=bucket_name)
                bucket_info["website"] = website
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchWebsiteConfiguration":
                    print(f"    ⚠ Error getting website: {e} (continuing)")
            
            # Public access block
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                bucket_info["public_access_block"] = public_access.get("PublicAccessBlockConfiguration", {})
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlockConfiguration":
                    print(f"    ⚠ Error getting public access block: {e} (continuing)")
            
            # Logging
            try:
                logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                bucket_info["logging"] = logging.get("LoggingEnabled", {})
            except Exception as e:
                print(f"    ⚠ Error getting logging: {e} (continuing)")
            
            # Versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                bucket_info["versioning"] = {
                    "Status": versioning.get("Status"),
                    "MfaDelete": versioning.get("MfaDelete"),
                }
            except Exception as e:
                print(f"    ⚠ Error getting versioning: {e} (continuing)")
            
            # Notifications
            try:
                notifications = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                bucket_info["notifications"] = {
                    "TopicConfigurations": notifications.get("TopicConfigurations", []),
                    "QueueConfigurations": notifications.get("QueueConfigurations", []),
                    "LambdaFunctionConfigurations": notifications.get("LambdaFunctionConfigurations", []),
                    "EventBridgeConfiguration": notifications.get("EventBridgeConfiguration", {}),
                }
            except Exception as e:
                print(f"    ⚠ Error getting notifications: {e} (continuing)")
            
            # Tags
            try:
                tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
                bucket_info["tags"] = {tag["Key"]: tag["Value"] for tag in tagging.get("TagSet", [])}
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchTagSet":
                    print(f"    ⚠ Error getting tags: {e} (continuing)")
            
            all_data["BucketInfo"] = bucket_info
            print(f"    ✓ Collected bucket info")
        except Exception as e:
            print(f"    ⚠ Error collecting bucket info: {e} (continuing)")
        
        # 2. Collect access information
        print("[+] Collecting access information...")
        try:
            access_data = {}
            
            # Public access check
            try:
                public_access = _check_public_access(s3_client, bucket_name)
                access_data["public_access"] = public_access
            except Exception as e:
                print(f"    ⚠ Error checking public access: {e} (continuing)")
            
            # Access points
            try:
                from ventra.auth.store import get_active_profile
                profile_name, creds = get_active_profile()
                sts_client = boto3.Session(
                    aws_access_key_id=creds["access_key"],
                    aws_secret_access_key=creds["secret_key"],
                    region_name=args.region,
                ).client("sts")
                account_id = sts_client.get_caller_identity().get("Account")
                
                access_points = []
                try:
                    paginator = s3control_client.get_paginator("list_access_points")
                    for page in paginator.paginate(AccountId=account_id, Bucket=bucket_name):
                        for ap in page.get("AccessPointList", []):
                            access_point_arn = ap.get("AccessPointArn")
                            access_point_name = ap.get("Name")
                            
                            ap_info = {
                                "Name": access_point_name,
                                "AccessPointArn": access_point_arn,
                                "NetworkOrigin": ap.get("NetworkOrigin"),
                                "VpcConfiguration": ap.get("VpcConfiguration"),
                                "Policy": None,
                            }
                            
                            try:
                                ap_policy = s3control_client.get_access_point_policy(
                                    AccountId=account_id,
                                    Name=access_point_name
                                )
                                ap_info["Policy"] = json.loads(ap_policy.get("Policy", "{}"))
                            except Exception:
                                pass
                            
                            access_points.append(ap_info)
                except Exception as e:
                    print(f"    ⚠ Error listing access points: {e} (continuing)")
                
                access_data["access_points"] = access_points
            except Exception as e:
                print(f"    ⚠ Error collecting access points: {e} (continuing)")
            
            # Cross-account analysis
            try:
                cross_account = []
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy.get("Policy", "{}"))
                    
                    for statement in policy_doc.get("Statement", []):
                        principal = statement.get("Principal", {})
                        if isinstance(principal, dict):
                            aws_principals = principal.get("AWS", [])
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for aws_principal in aws_principals:
                                if aws_principal != "*" and "arn:aws:iam" in aws_principal:
                                    parts = aws_principal.split(":")
                                    if len(parts) >= 5:
                                        principal_account = parts[4]
                                        if principal_account != account_id:
                                            cross_account.append({
                                                "Principal": aws_principal,
                                                "AccountId": principal_account,
                                                "Action": statement.get("Action", []),
                                                "Effect": statement.get("Effect"),
                                            })
                except ClientError:
                    pass
                
                access_data["cross_account_principals"] = cross_account
            except Exception as e:
                print(f"    ⚠ Error analyzing cross-account access: {e} (continuing)")
            
            all_data["Access"] = access_data
            print(f"    ✓ Collected access info")
        except Exception as e:
            print(f"    ⚠ Error collecting access info: {e} (continuing)")
        
        # 3. Collect objects
        print("[+] Collecting objects...")
        try:
            objects_list = []
            common_prefixes_list = []
            object_count = 0
            
            paginator = s3_client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(
                Bucket=bucket_name,
                Prefix=prefix if prefix else "",
                Delimiter=""
            )
            
            for page in page_iterator:
                for obj in page.get("Contents", []):
                    if limit and object_count >= limit:
                        break
                    
                    obj_info = {
                        "Key": obj.get("Key"),
                        "Size": obj.get("Size"),
                        "LastModified": str(obj.get("LastModified", "")),
                        "ETag": obj.get("ETag", "").strip('"'),
                        "StorageClass": obj.get("StorageClass"),
                        "Owner": obj.get("Owner", {}),
                    }
                    objects_list.append(obj_info)
                    object_count += 1
                    
                    if object_count % 1000 == 0:
                        print(f"    ... Listed {object_count} objects so far...")
                
                if limit and object_count >= limit:
                    break
                
                for prefix_item in page.get("CommonPrefixes", []):
                    common_prefixes_list.append(prefix_item.get("Prefix"))
            
            all_data["Objects"]["objects"] = objects_list
            all_data["Objects"]["common_prefixes"] = common_prefixes_list
            all_data["Objects"]["total_objects"] = len(objects_list)
            all_data["Objects"]["total_prefixes"] = len(common_prefixes_list)
            print(f"    ✓ Listed {len(objects_list)} object(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting objects: {e} (continuing)")
        
        # 4. Collect versions
        print("[+] Collecting object versions...")
        try:
            # Check versioning first
            versioning_status = "NotEnabled"
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning.get("Status", "NotEnabled")
            except Exception:
                pass
            
            if versioning_status == "Enabled":
                versions_list = []
                delete_markers_list = []
                
                paginator = s3_client.get_paginator("list_object_versions")
                page_iterator = paginator.paginate(
                    Bucket=bucket_name,
                    Prefix=prefix if prefix else "",
                )
                
                for page in page_iterator:
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
                        versions_list.append(version_info)
                    
                    for delete_marker in page.get("DeleteMarkers", []):
                        marker_info = {
                            "Key": delete_marker.get("Key"),
                            "VersionId": delete_marker.get("VersionId"),
                            "IsLatest": delete_marker.get("IsLatest"),
                            "LastModified": str(delete_marker.get("LastModified", "")),
                            "Owner": delete_marker.get("Owner", {}),
                        }
                        delete_markers_list.append(marker_info)
                
                all_data["Versions"]["versions"] = versions_list
                all_data["Versions"]["delete_markers"] = delete_markers_list
                all_data["Versions"]["versioning_status"] = versioning_status
                all_data["Versions"]["total_versions"] = len(versions_list)
                all_data["Versions"]["total_delete_markers"] = len(delete_markers_list)
                print(f"    ✓ Listed {len(versions_list)} version(s), {len(delete_markers_list)} delete marker(s)")
            else:
                all_data["Versions"]["versioning_status"] = versioning_status
                all_data["Versions"]["message"] = "Versioning is not enabled for this bucket"
                print(f"    ⚠ Versioning not enabled, skipping versions")
        except Exception as e:
            print(f"    ⚠ Error collecting versions: {e} (continuing)")
        
        # Save combined file
        safe_bucket_name = bucket_name.replace("/", "_").replace(" ", "_")
        safe_prefix = prefix.replace("/", "_").replace(" ", "_") if prefix else "root"
        filename = f"s3_{safe_bucket_name}_{safe_prefix}_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all S3 data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
