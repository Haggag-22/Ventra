"""
IAM Policies Collector
Collects comprehensive IAM managed policy information.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_iam_client(region):
    """IAM client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("iam")


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


def _save_jsonl_file(output_dir, filename, data_list):
    """Save data to JSONL file (one JSON object per line)."""
    filepath = os.path.join(output_dir, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            for item in data_list:
                f.write(json.dumps(item, default=str) + "\n")
        return filepath
    except Exception as e:
        print(f"    ❌ Error saving {filename}: {e}")
        return None


def collect_policy_metadata(iam_client, policy_arn, output_dir):
    """Collect policy metadata."""
    try:
        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_data = {
            "PolicyName": policy_response.get("Policy", {}).get("PolicyName"),
            "PolicyId": policy_response.get("Policy", {}).get("PolicyId"),
            "Arn": policy_response.get("Policy", {}).get("Arn"),
            "Path": policy_response.get("Policy", {}).get("Path"),
            "DefaultVersionId": policy_response.get("Policy", {}).get("DefaultVersionId"),
            "AttachmentCount": policy_response.get("Policy", {}).get("AttachmentCount"),
            "PermissionsBoundaryUsageCount": policy_response.get("Policy", {}).get("PermissionsBoundaryUsageCount"),
            "IsAttachable": policy_response.get("Policy", {}).get("IsAttachable"),
            "Description": policy_response.get("Policy", {}).get("Description"),
            "CreateDate": str(policy_response.get("Policy", {}).get("CreateDate", "")),
            "UpdateDate": str(policy_response.get("Policy", {}).get("UpdateDate", "")),
            "Tags": policy_response.get("Policy", {}).get("Tags", []),
        }
        if output_dir:
            _save_json_file(output_dir, "policy.json", policy_data)
        return policy_data
    except ClientError as e:
        print(f"    ❌ Error getting policy: {e}")
        return None


def collect_policy_versions(iam_client, policy_arn, output_dir):
    """Collect all policy versions."""
    policy_versions = []
    try:
        paginator = iam_client.get_paginator("list_policy_versions")
        for page in paginator.paginate(PolicyArn=policy_arn):
            for version in page.get("Versions", []):
                version_id = version.get("VersionId")
                version_info = {
                    "VersionId": version_id,
                    "IsDefaultVersion": version.get("IsDefaultVersion"),
                    "CreateDate": str(version.get("CreateDate", "")),
                }
                
                # Get the actual policy document for this version
                try:
                    version_response = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )
                    version_info["PolicyDocument"] = version_response.get("PolicyVersion", {}).get("Document")
                except ClientError as e:
                    print(f"      ⚠ Error getting policy version {version_id}: {e}")
                
                policy_versions.append(version_info)
    except ClientError as e:
        print(f"    ⚠ Error listing policy versions: {e}")
    
    if output_dir:
        _save_jsonl_file(output_dir, "policy_versions.jsonl", policy_versions)
    return policy_versions


def run_iam_policy(args):
    """Collect comprehensive IAM information for a single managed policy."""
    policy_arn = args.arn
    print(f"[+] IAM Policy Collector")
    print(f"    Policy ARN:   {policy_arn}")
    print(f"    Region:      {args.region}\n")
    
    # Extract policy name from ARN for filename
    policy_name = policy_arn.split("/")[-1] if "/" in policy_arn else policy_arn.split(":")[-1]
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")

    # Resources collectors must write under the case's resources/ directory
    output_dir = os.path.join(output_dir, "resources", "iam")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        iam_client = _get_iam_client(args.region)
    except Exception as e:
        print(f"❌ Error getting IAM client: {e}")
        return
    
    try:
        # Collect all data into a single structure
        policy_data = {}
        
        print(f"[+] Collecting policy metadata...")
        policy_metadata = collect_policy_metadata(iam_client, policy_arn, None)
        policy_data["policy"] = policy_metadata if policy_metadata else {}
        if policy_metadata:
            print(f"    ✓ Collected policy metadata")
        else:
            print(f"    ⚠ No policy metadata found (continuing with available data)")
        
        print(f"[+] Collecting policy versions...")
        policy_versions = collect_policy_versions(iam_client, policy_arn, None)
        policy_data["policy_versions"] = policy_versions
        print(f"    ✓ Collected {len(policy_versions)} policy version(s)")
        
        # Save single combined file
        filename = f"policy_{policy_name}.json"
        filepath = _save_json_file(output_dir, filename, policy_data)
        if filepath:
            print(f"\n[✓] Saved all policy data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

