"""
IAM Groups Collector
Collects comprehensive IAM group information.
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


def collect_group_metadata(iam_client, group_name, output_dir):
    """Collect group metadata."""
    try:
        group_response = iam_client.get_group(GroupName=group_name)
        group_data = {
            "GroupName": group_response.get("Group", {}).get("GroupName"),
            "GroupId": group_response.get("Group", {}).get("GroupId"),
            "Arn": group_response.get("Group", {}).get("Arn"),
            "Path": group_response.get("Group", {}).get("Path"),
            "CreateDate": str(group_response.get("Group", {}).get("CreateDate", "")),
        }
        if output_dir:
            _save_json_file(output_dir, "group.json", group_data)
        return group_data
    except ClientError as e:
        print(f"    ❌ Error getting group: {e}")
        return None


def collect_group_inline_policies(iam_client, group_name, output_dir):
    """Collect all inline policies for a group."""
    inline_policies = []
    try:
        paginator = iam_client.get_paginator("list_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            for policy_name in page.get("PolicyNames", []):
                try:
                    policy_response = iam_client.get_group_policy(
                        GroupName=group_name,
                        PolicyName=policy_name
                    )
                    inline_policies.append({
                        "PolicyName": policy_name,
                        "PolicyDocument": policy_response.get("PolicyDocument"),
                    })
                except ClientError as e:
                    print(f"      ⚠ Error getting inline policy {policy_name}: {e}")
    except ClientError as e:
        print(f"    ⚠ Error listing inline policies: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "inline_policies.json", inline_policies)
    return inline_policies


def collect_group_attached_policies(iam_client, group_name, output_dir):
    """Collect all attached managed policies for a group."""
    attached_policies = []
    try:
        paginator = iam_client.get_paginator("list_attached_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            for policy in page.get("AttachedPolicies", []):
                attached_policies.append({
                    "PolicyArn": policy.get("PolicyArn"),
                    "PolicyName": policy.get("PolicyName"),
                })
    except ClientError as e:
        print(f"    ⚠ Error listing attached policies: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "attached_policies.json", attached_policies)
    return attached_policies


def run_iam_group(args):
    """Collect comprehensive IAM information for a single group."""
    group_name = args.name
    print(f"[+] IAM Group Collector")
    print(f"    Group:       {group_name}")
    print(f"    Region:      {args.region}\n")
    
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
        group_data = {}
        
        print(f"[+] Collecting group metadata...")
        group_metadata = collect_group_metadata(iam_client, group_name, None)
        group_data["group"] = group_metadata if group_metadata else {}
        if group_metadata:
            print(f"    ✓ Collected group metadata")
        else:
            print(f"    ⚠ No group metadata found (continuing with available data)")
        
        print(f"[+] Collecting inline policies...")
        inline_policies = collect_group_inline_policies(iam_client, group_name, None)
        group_data["inline_policies"] = inline_policies
        print(f"    ✓ Collected {len(inline_policies)} inline policy/policies")
        
        print(f"[+] Collecting attached managed policies...")
        attached_policies = collect_group_attached_policies(iam_client, group_name, None)
        group_data["attached_policies"] = attached_policies
        print(f"    ✓ Collected {len(attached_policies)} attached policy/policies")
        
        # Save single combined file
        filename = f"group_{group_name}.json"
        filepath = _save_json_file(output_dir, filename, group_data)
        if filepath:
            print(f"\n[✓] Saved all group data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

