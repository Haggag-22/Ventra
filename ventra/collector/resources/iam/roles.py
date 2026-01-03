"""
IAM Roles Collector
Collects comprehensive IAM role information.
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


def collect_role_metadata(iam_client, role_name, output_dir):
    """Collect role metadata."""
    try:
        role_response = iam_client.get_role(RoleName=role_name)
        role_data = {
            "RoleName": role_response.get("Role", {}).get("RoleName"),
            "RoleId": role_response.get("Role", {}).get("RoleId"),
            "Arn": role_response.get("Role", {}).get("Arn"),
            "Path": role_response.get("Role", {}).get("Path"),
            "CreateDate": str(role_response.get("Role", {}).get("CreateDate", "")),
            "AssumeRolePolicyDocument": role_response.get("Role", {}).get("AssumeRolePolicyDocument"),
            "Description": role_response.get("Role", {}).get("Description"),
            "MaxSessionDuration": role_response.get("Role", {}).get("MaxSessionDuration"),
            "PermissionsBoundary": role_response.get("Role", {}).get("PermissionsBoundary"),
            "Tags": role_response.get("Role", {}).get("Tags", []),
            "RoleLastUsed": role_response.get("Role", {}).get("RoleLastUsed"),
        }
        if output_dir:
            _save_json_file(output_dir, "role.json", role_data)
        return role_data
    except ClientError as e:
        print(f"    ❌ Error getting role: {e}")
        return None


def collect_role_inline_policies(iam_client, role_name, output_dir):
    """Collect all inline policies for a role."""
    inline_policies = []
    try:
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page.get("PolicyNames", []):
                try:
                    policy_response = iam_client.get_role_policy(
                        RoleName=role_name,
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


def collect_role_attached_policies(iam_client, role_name, output_dir):
    """Collect all attached managed policies for a role."""
    attached_policies = []
    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
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


def collect_role_trust_policy(iam_client, role_name, output_dir):
    """Collect trust policy (AssumeRolePolicyDocument) for a role."""
    trust_policy = None
    try:
        role_response = iam_client.get_role(RoleName=role_name)
        trust_policy = role_response.get("Role", {}).get("AssumeRolePolicyDocument")
        if trust_policy and output_dir:
            _save_json_file(output_dir, "trust_policy.json", trust_policy)
    except ClientError as e:
        print(f"    ⚠ Error getting trust policy: {e}")
    
    return trust_policy


def run_iam_role(args):
    """Collect comprehensive IAM information for a single role."""
    role_name = args.name
    print(f"[+] IAM Role Collector")
    print(f"    Role:        {role_name}")
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
        role_data = {}
        
        print(f"[+] Collecting role metadata...")
        role_metadata = collect_role_metadata(iam_client, role_name, None)
        role_data["role"] = role_metadata if role_metadata else {}
        if role_metadata:
            print(f"    ✓ Collected role metadata")
        else:
            print(f"    ⚠ No role metadata found (continuing with available data)")
        
        print(f"[+] Collecting inline policies...")
        inline_policies = collect_role_inline_policies(iam_client, role_name, None)
        role_data["inline_policies"] = inline_policies
        print(f"    ✓ Collected {len(inline_policies)} inline policy/policies")
        
        print(f"[+] Collecting attached managed policies...")
        attached_policies = collect_role_attached_policies(iam_client, role_name, None)
        role_data["attached_policies"] = attached_policies
        print(f"    ✓ Collected {len(attached_policies)} attached policy/policies")
        
        print(f"[+] Collecting trust policy...")
        trust_policy = collect_role_trust_policy(iam_client, role_name, None)
        role_data["trust_policy"] = trust_policy
        if trust_policy:
            print(f"    ✓ Collected trust policy")
        
        # Save single combined file
        filename = f"role_{role_name}.json"
        filepath = _save_json_file(output_dir, filename, role_data)
        if filepath:
            print(f"\n[✓] Saved all role data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

