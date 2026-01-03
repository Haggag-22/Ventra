"""
S3 Bucket Policies Collector
Collects S3 bucket policy documents.
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


def run_s3_bucket_policies(args):
    """Collect S3 bucket policy documents."""
    bucket_name = args.bucket
    print(f"[+] S3 Bucket Policies Collector")
    print(f"    Bucket:      {bucket_name}")
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
        # Get bucket policy
        print("[+] Collecting bucket policy...")
        policy_data = {}
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy.get("Policy", "{}"))
            policy_data = {
                "BucketName": bucket_name,
                "Policy": policy_doc,
                "PolicyRaw": policy.get("Policy"),
            }
            print(f"    ✓ Collected policy")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucketPolicy":
                policy_data = {
                    "BucketName": bucket_name,
                    "Policy": None,
                    "PolicyRaw": None,
                }
                print(f"    ⚠ No bucket policy")
            else:
                print(f"    ⚠ Error getting policy: {e}")
                policy_data = {
                    "BucketName": bucket_name,
                    "Policy": None,
                    "Error": str(e),
                }
        
        # Save policy
        filename = f"s3_bucket_policies_{bucket_name}.json"
        filepath = _save_json_file(output_dir, filename, policy_data)
        if filepath:
            print(f"\n[✓] Saved bucket policy → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")







