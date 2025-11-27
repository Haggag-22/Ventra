"""
IAM Collector Module - Main orchestrator
Collects comprehensive IAM account-wide information.
"""
import os
import json
import boto3
import base64
from datetime import datetime
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile
from ventra.collector.iam.users import run_iam_user
from ventra.collector.iam.roles import run_iam_role
from ventra.collector.iam.groups import run_iam_group
from ventra.collector.iam.policies import run_iam_policy


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


def _resolve_output_dir(args):
    """Resolve output directory."""
    if hasattr(args, "case_dir") and args.case_dir:
        output_base = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_base = args.output
    else:
        output_base = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    os.makedirs(output_base, exist_ok=True)
    return output_base


def collect_all_users(iam_client, output_base):
    """Collect list of all users."""
    print("[+] Collecting all IAM users...")
    all_users = []
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                all_users.append({
                    "UserName": user.get("UserName"),
                    "UserId": user.get("UserId"),
                    "Arn": user.get("Arn"),
                    "Path": user.get("Path"),
                    "CreateDate": str(user.get("CreateDate", "")),
                    "PasswordLastUsed": str(user.get("PasswordLastUsed", "")) if user.get("PasswordLastUsed") else None,
                })
        print(f"    ✓ Found {len(all_users)} user(s)")
    except ClientError as e:
        print(f"    ❌ Error listing users: {e}")
    
    if output_base:
        iam_dir = os.path.join(output_base, "iam")
        os.makedirs(iam_dir, exist_ok=True)
        _save_json_file(iam_dir, "all_users.json", all_users)
    return all_users


def collect_all_roles(iam_client, output_base):
    """Collect list of all roles."""
    print("[+] Collecting all IAM roles...")
    all_roles = []
    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                all_roles.append({
                    "RoleName": role.get("RoleName"),
                    "RoleId": role.get("RoleId"),
                    "Arn": role.get("Arn"),
                    "Path": role.get("Path"),
                    "CreateDate": str(role.get("CreateDate", "")),
                    "Description": role.get("Description"),
                    "MaxSessionDuration": role.get("MaxSessionDuration"),
                })
        print(f"    ✓ Found {len(all_roles)} role(s)")
    except ClientError as e:
        print(f"    ❌ Error listing roles: {e}")
    
    if output_base:
        iam_dir = os.path.join(output_base, "iam")
        os.makedirs(iam_dir, exist_ok=True)
        _save_json_file(iam_dir, "all_roles.json", all_roles)
    return all_roles


def collect_all_groups(iam_client, output_base):
    """Collect list of all groups."""
    print("[+] Collecting all IAM groups...")
    all_groups = []
    try:
        paginator = iam_client.get_paginator("list_groups")
        for page in paginator.paginate():
            for group in page.get("Groups", []):
                all_groups.append({
                    "GroupName": group.get("GroupName"),
                    "GroupId": group.get("GroupId"),
                    "Arn": group.get("Arn"),
                    "Path": group.get("Path"),
                    "CreateDate": str(group.get("CreateDate", "")),
                })
        print(f"    ✓ Found {len(all_groups)} group(s)")
    except ClientError as e:
        print(f"    ❌ Error listing groups: {e}")
    
    if output_base:
        iam_dir = os.path.join(output_base, "iam")
        os.makedirs(iam_dir, exist_ok=True)
        _save_json_file(iam_dir, "all_groups.json", all_groups)
    return all_groups


def collect_all_policies(iam_client, output_base):
    """Collect list of all managed policies."""
    print("[+] Collecting all IAM managed policies...")
    all_policies = []
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="All"):
            for policy in page.get("Policies", []):
                all_policies.append({
                    "PolicyName": policy.get("PolicyName"),
                    "PolicyId": policy.get("PolicyId"),
                    "Arn": policy.get("Arn"),
                    "Path": policy.get("Path"),
                    "DefaultVersionId": policy.get("DefaultVersionId"),
                    "AttachmentCount": policy.get("AttachmentCount"),
                    "IsAttachable": policy.get("IsAttachable"),
                    "Description": policy.get("Description"),
                    "CreateDate": str(policy.get("CreateDate", "")),
                    "UpdateDate": str(policy.get("UpdateDate", "")),
                })
        print(f"    ✓ Found {len(all_policies)} policy/policies")
    except ClientError as e:
        print(f"    ❌ Error listing policies: {e}")
    
    iam_dir = os.path.join(output_base, "iam")
    os.makedirs(iam_dir, exist_ok=True)
    _save_json_file(iam_dir, "all_policies.json", all_policies)
    return all_policies


def collect_service_linked_roles(iam_client, output_base):
    """Collect service-linked roles."""
    print("[+] Collecting service-linked roles...")
    service_linked_roles = []
    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                if role.get("Arn", "").startswith("arn:aws:iam::") and "/aws-service-role/" in role.get("Arn", ""):
                    service_linked_roles.append({
                        "RoleName": role.get("RoleName"),
                        "RoleId": role.get("RoleId"),
                        "Arn": role.get("Arn"),
                        "Path": role.get("Path"),
                        "CreateDate": str(role.get("CreateDate", "")),
                    })
        print(f"    ✓ Found {len(service_linked_roles)} service-linked role(s)")
    except ClientError as e:
        print(f"    ❌ Error listing service-linked roles: {e}")
    
    iam_dir = os.path.join(output_base, "iam")
    os.makedirs(iam_dir, exist_ok=True)
    _save_json_file(iam_dir, "service_linked_roles.json", service_linked_roles)
    return service_linked_roles


def collect_account_password_policy(iam_client, output_base):
    """Collect account password policy."""
    print("[+] Collecting account password policy...")
    password_policy = None
    try:
        policy_response = iam_client.get_account_password_policy()
        password_policy = {
            "MinimumPasswordLength": policy_response.get("PasswordPolicy", {}).get("MinimumPasswordLength"),
            "RequireSymbols": policy_response.get("PasswordPolicy", {}).get("RequireSymbols"),
            "RequireNumbers": policy_response.get("PasswordPolicy", {}).get("RequireNumbers"),
            "RequireUppercaseCharacters": policy_response.get("PasswordPolicy", {}).get("RequireUppercaseCharacters"),
            "RequireLowercaseCharacters": policy_response.get("PasswordPolicy", {}).get("RequireLowercaseCharacters"),
            "AllowUsersToChangePassword": policy_response.get("PasswordPolicy", {}).get("AllowUsersToChangePassword"),
            "ExpirePasswords": policy_response.get("PasswordPolicy", {}).get("ExpirePasswords"),
            "MaxPasswordAge": policy_response.get("PasswordPolicy", {}).get("MaxPasswordAge"),
            "PasswordReusePrevention": policy_response.get("PasswordPolicy", {}).get("PasswordReusePrevention"),
            "HardExpiry": policy_response.get("PasswordPolicy", {}).get("HardExpiry"),
        }
        print(f"    ✓ Collected password policy")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchEntity":
            password_policy = {"PasswordPolicy": None}
            print(f"    ⚠ No password policy configured")
        else:
            print(f"    ❌ Error getting password policy: {e}")
    
    if password_policy:
        iam_dir = os.path.join(output_base, "iam")
        os.makedirs(iam_dir, exist_ok=True)
        _save_json_file(iam_dir, "account_password_policy.json", password_policy)
    return password_policy


def collect_account_summary(iam_client, output_base):
    """Collect account summary."""
    print("[+] Collecting account summary...")
    account_summary = None
    try:
        summary_response = iam_client.get_account_summary()
        account_summary = summary_response.get("SummaryMap", {})
        print(f"    ✓ Collected account summary")
    except ClientError as e:
        print(f"    ❌ Error getting account summary: {e}")
    
    if account_summary:
        iam_dir = os.path.join(output_base, "iam")
        os.makedirs(iam_dir, exist_ok=True)
        _save_json_file(iam_dir, "account_summary.json", account_summary)
    return account_summary


def collect_credential_report(iam_client, output_base):
    """Collect IAM credential report."""
    print("[+] Collecting IAM credential report...")
    credential_report = None
    try:
        # Generate or get existing report
        try:
            report_response = iam_client.generate_credential_report()
            if report_response.get("State") == "COMPLETE":
                pass  # Report already exists
        except ClientError:
            # Try to get existing report
            pass
        
        # Wait a bit and get the report
        import time
        time.sleep(2)
        
        report_response = iam_client.get_credential_report()
        report_content = base64.b64decode(report_response.get("Content", b"")).decode("utf-8")
        
        # Parse CSV report into structured data
        lines = report_content.strip().split("\n")
        if len(lines) > 1:
            headers = lines[0].split(",")
            credential_report = []
            for line in lines[1:]:
                values = line.split(",")
                if len(values) == len(headers):
                    report_entry = dict(zip(headers, values))
                    credential_report.append(report_entry)
        
        print(f"    ✓ Collected credential report ({len(credential_report) if credential_report else 0} entries)")
    except ClientError as e:
        print(f"    ⚠ Error getting credential report: {e}")
    
    if credential_report:
        iam_dir = os.path.join(output_base, "iam")
        os.makedirs(iam_dir, exist_ok=True)
        _save_json_file(iam_dir, "credential_report.json", credential_report)
    return credential_report


def generate_master_index(output_base, all_users, all_roles, all_groups, all_policies):
    """Generate master index file summarizing all IAM entities."""
    print("[+] Generating master index...")
    
    index = {
        "CollectionTimestamp": datetime.utcnow().isoformat() + "Z",
        "Summary": {
            "TotalUsers": len(all_users),
            "TotalRoles": len(all_roles),
            "TotalGroups": len(all_groups),
            "TotalPolicies": len(all_policies),
        },
        "Users": [{"UserName": u.get("UserName"), "Arn": u.get("Arn")} for u in all_users],
        "Roles": [{"RoleName": r.get("RoleName"), "Arn": r.get("Arn")} for r in all_roles],
        "Groups": [{"GroupName": g.get("GroupName"), "Arn": g.get("Arn")} for g in all_groups],
        "Policies": [{"PolicyName": p.get("PolicyName"), "Arn": p.get("Arn")} for p in all_policies],
    }
    
    iam_dir = os.path.join(output_base, "iam")
    os.makedirs(iam_dir, exist_ok=True)
    filepath = _save_json_file(iam_dir, "master_index.json", index)
    if filepath:
        print(f"    ✓ Saved master index → {filepath}")
    return index


def run_iam_all(args):
    """Collect comprehensive IAM information for the entire account."""
    print(f"[+] IAM Full Account Collector")
    print(f"    Region:      {args.region}\n")
    
    output_dir = _resolve_output_dir(args)
    print(f"    Output:      {output_dir}\n")
    
    try:
        iam_client = _get_iam_client(args.region)
    except Exception as e:
        print(f"❌ Error getting IAM client: {e}")
        return
    
    try:
        # Collect all data into a single structure
        all_data = {}
        
        print("=" * 60)
        print("[+] Phase 1: Collecting account-wide IAM information")
        print("=" * 60 + "\n")
        
        all_users = collect_all_users(iam_client, None)
        all_roles = collect_all_roles(iam_client, None)
        all_groups = collect_all_groups(iam_client, None)
        all_policies = collect_all_policies(iam_client, None)
        service_linked_roles = collect_service_linked_roles(iam_client, None)
        password_policy = collect_account_password_policy(iam_client, None)
        account_summary = collect_account_summary(iam_client, None)
        credential_report = collect_credential_report(iam_client, None)
        
        # Add to combined structure
        all_data["all_users"] = all_users
        all_data["all_roles"] = all_roles
        all_data["all_groups"] = all_groups
        all_data["all_policies"] = all_policies
        all_data["service_linked_roles"] = service_linked_roles
        all_data["account_password_policy"] = password_policy
        all_data["account_summary"] = account_summary
        all_data["credential_report"] = credential_report
        
        # Generate master index
        master_index = generate_master_index(None, all_users, all_roles, all_groups, all_policies)
        all_data["master_index"] = master_index
        
        # Collect detailed information for each entity
        print("\n" + "=" * 60)
        print("[+] Phase 2: Collecting detailed information for each entity")
        print("=" * 60 + "\n")
        
        # Collect all users
        all_data["users_detail"] = {}
        if all_users:
            print(f"[+] Collecting detailed information for {len(all_users)} user(s)...\n")
            for idx, user in enumerate(all_users, 1):
                username = user.get("UserName")
                print(f"[{idx}/{len(all_users)}] Processing user: {username}")
                user_args = type('Args', (), {
                    'name': username,
                    'region': args.region,
                    'case_dir': args.case_dir if hasattr(args, 'case_dir') else None,
                    'output': getattr(args, 'output', None),
                })()
                # Collect user data but don't save individual files
                from ventra.collector.iam.users import (
                    collect_user_identity, collect_user_inline_policies,
                    collect_user_attached_policies, collect_user_groups,
                    collect_user_access_keys, collect_user_mfa_devices,
                    collect_user_signing_certificates, collect_user_ssh_public_keys,
                    collect_user_service_specific_credentials, collect_user_login_profile
                )
                user_detail = {
                    "user": collect_user_identity(iam_client, username, None),
                    "inline_policies": collect_user_inline_policies(iam_client, username, None),
                    "attached_policies": collect_user_attached_policies(iam_client, username, None),
                    "groups": collect_user_groups(iam_client, username, None),
                    "access_keys": collect_user_access_keys(iam_client, username, None),
                    "mfa_devices": collect_user_mfa_devices(iam_client, username, None),
                    "signing_certificates": collect_user_signing_certificates(iam_client, username, None),
                    "ssh_public_keys": collect_user_ssh_public_keys(iam_client, username, None),
                    "service_specific_credentials": collect_user_service_specific_credentials(iam_client, username, None),
                    "login_profile": collect_user_login_profile(iam_client, username, None),
                }
                all_data["users_detail"][username] = user_detail
        
        # Collect all roles
        all_data["roles_detail"] = {}
        if all_roles:
            print(f"[+] Collecting detailed information for {len(all_roles)} role(s)...\n")
            for idx, role in enumerate(all_roles, 1):
                role_name = role.get("RoleName")
                print(f"[{idx}/{len(all_roles)}] Processing role: {role_name}")
                from ventra.collector.iam.roles import (
                    collect_role_metadata, collect_role_inline_policies,
                    collect_role_attached_policies, collect_role_trust_policy
                )
                role_detail = {
                    "role": collect_role_metadata(iam_client, role_name, None),
                    "inline_policies": collect_role_inline_policies(iam_client, role_name, None),
                    "attached_policies": collect_role_attached_policies(iam_client, role_name, None),
                    "trust_policy": collect_role_trust_policy(iam_client, role_name, None),
                }
                all_data["roles_detail"][role_name] = role_detail
        
        # Collect all groups
        all_data["groups_detail"] = {}
        if all_groups:
            print(f"[+] Collecting detailed information for {len(all_groups)} group(s)...\n")
            for idx, group in enumerate(all_groups, 1):
                group_name = group.get("GroupName")
                print(f"[{idx}/{len(all_groups)}] Processing group: {group_name}")
                from ventra.collector.iam.groups import (
                    collect_group_metadata, collect_group_inline_policies,
                    collect_group_attached_policies
                )
                group_detail = {
                    "group": collect_group_metadata(iam_client, group_name, None),
                    "inline_policies": collect_group_inline_policies(iam_client, group_name, None),
                    "attached_policies": collect_group_attached_policies(iam_client, group_name, None),
                }
                all_data["groups_detail"][group_name] = group_detail
        
        # Collect all policies
        all_data["policies_detail"] = {}
        if all_policies:
            print(f"[+] Collecting detailed information for {len(all_policies)} policy/policies...\n")
            for idx, policy in enumerate(all_policies, 1):
                policy_arn = policy.get("Arn")
                policy_name = policy_arn.split("/")[-1] if "/" in policy_arn else policy_arn.split(":")[-1]
                print(f"[{idx}/{len(all_policies)}] Processing policy: {policy_arn}")
                from ventra.collector.iam.policies import (
                    collect_policy_metadata, collect_policy_versions
                )
                policy_detail = {
                    "policy": collect_policy_metadata(iam_client, policy_arn, None),
                    "policy_versions": collect_policy_versions(iam_client, policy_arn, None),
                }
                all_data["policies_detail"][policy_name] = policy_detail
        
        # Save single combined file
        filename = "iam_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all IAM account data → {filepath}\n")
        
        print("\n" + "=" * 60)
        print("[✓] Completed full IAM account collection")
        print("=" * 60 + "\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
