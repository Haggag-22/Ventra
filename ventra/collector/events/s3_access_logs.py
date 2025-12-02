"""
S3 Access Collector
Collects access points, access-point policies, cross-account principals, and public exposure checks.
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
    return session.client("s3control")


def _get_s3_regular_client(region):
    """Regular S3 client for bucket operations."""
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
            # Simple check for public access in policy
            policy_str = json.dumps(policy_doc)
            if '"Principal": "*"' in policy_str or '"Principal": {"AWS": "*"}' in policy_str:
                public_access["is_public"] = True
        except ClientError:
            pass
            
    except ClientError as e:
        print(f"    ⚠ Error checking public access: {e}")
    
    return public_access


def run_s3_access_logs(args):
    """Collect S3 access information."""
    bucket_name = args.bucket
    print(f"[+] S3 Access Collector")
    print(f"    Bucket:      {bucket_name}")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "events")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        s3_client = _get_s3_regular_client(args.region)
        s3control_client = _get_s3_client(args.region)
    except Exception as e:
        print(f"❌ Error getting S3 client: {e}")
        return
    
    try:
        # Get account ID
        from ventra.auth.store import get_active_profile
        profile_name, creds = get_active_profile()
        sts_client = boto3.Session(
            aws_access_key_id=creds["access_key"],
            aws_secret_access_key=creds["secret_key"],
            region_name=args.region,
        ).client("sts")
        account_id = sts_client.get_caller_identity().get("Account")
        
        access_data = {}
        
        # Check public access
        print("[+] Checking public access...")
        public_access = _check_public_access(s3_client, bucket_name)
        access_data["public_access"] = public_access
        if public_access["is_public"]:
            print(f"    ⚠ Bucket is publicly accessible!")
        else:
            print(f"    ✓ Bucket is not publicly accessible")
        
        # List access points
        print("[+] Collecting access points...")
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
                    }
                    
                    # Get access point policy
                    try:
                        ap_policy = s3control_client.get_access_point_policy(
                            AccountId=account_id,
                            Name=access_point_name
                        )
                        ap_info["Policy"] = json.loads(ap_policy.get("Policy", "{}"))
                    except ClientError:
                        ap_info["Policy"] = None
                    
                    access_points.append(ap_info)
            
            print(f"    ✓ Found {len(access_points)} access point(s)")
        except ClientError as e:
            print(f"    ⚠ Error listing access points: {e}")
        
        access_data["access_points"] = access_points
        
        # Analyze bucket policy for cross-account access
        print("[+] Analyzing cross-account access...")
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
                            # Extract account ID
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
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "NoSuchBucketPolicy":
                print(f"    ⚠ Error analyzing policy: {e}")
        
        access_data["cross_account_principals"] = cross_account
        if cross_account:
            print(f"    ⚠ Found {len(cross_account)} cross-account principal(s)")
        else:
            print(f"    ✓ No cross-account access found")
        
        # Save single combined file
        filename = f"s3_access_logs_{bucket_name}.json"
        filepath = _save_json_file(output_dir, filename, access_data)
        if filepath:
            print(f"\n[✓] Saved access info → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

