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
from typing import Optional


def _permissions_boundary_arn(pb: dict) -> Optional[str]:
    """Extract PermissionsBoundaryArn from IAM PermissionsBoundary structure."""
    if not isinstance(pb, dict):
        return None
    return pb.get("PermissionsBoundaryArn")


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

    # Resources collectors must write under the case's resources/ directory.
    # Keep IAM outputs grouped under resources/iam/.
    output_base = os.path.join(output_base, "resources", "iam")
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
    """
    Collect list of IAM managed policies that are attached to something.
    (Filters out unattached policies to reduce noise/volume.)
    """
    print("[+] Collecting attached IAM managed policies...")
    all_policies = []
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="All"):
            for policy in page.get("Policies", []):
                # Only keep policies that are actually used somewhere
                attachment_count = policy.get("AttachmentCount") or 0
                pb_usage = policy.get("PermissionsBoundaryUsageCount") or 0
                if attachment_count <= 0 and pb_usage <= 0:
                    continue
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
    
    if output_base:
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
    
    if output_base:
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
    
    if password_policy and output_base:
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
    
    if account_summary and output_base:
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
        
        try:
            report_response = iam_client.get_credential_report()
            content = report_response.get("Content")
            
            if content:
                # Handle base64 decoding with padding fixes
                try:
                    # Add padding if needed
                    content_str = content if isinstance(content, str) else content.decode('utf-8')
                    # Fix padding
                    missing_padding = len(content_str) % 4
                    if missing_padding:
                        content_str += '=' * (4 - missing_padding)
                    report_content = base64.b64decode(content_str).decode("utf-8")
                    
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
                except (ValueError, UnicodeDecodeError, Exception) as e:
                    print(f"    ⚠ Error decoding credential report: {e}")
            else:
                print(f"    ⚠ Credential report content is empty")
        except ClientError as e:
            print(f"    ⚠ Error getting credential report: {e}")
    except Exception as e:
        print(f"    ⚠ Error collecting credential report: {e}")
    
    if credential_report and output_base:
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
    
    if output_base:
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
        
        # Collect all data with error handling - continue even if one fails
        try:
            all_users = collect_all_users(iam_client, None)
        except Exception as e:
            print(f"    ⚠ Error collecting users: {e} (continuing)")
            all_users = []
        
        try:
            all_roles = collect_all_roles(iam_client, None)
        except Exception as e:
            print(f"    ⚠ Error collecting roles: {e} (continuing)")
            all_roles = []
        
        try:
            all_groups = collect_all_groups(iam_client, None)
        except Exception as e:
            print(f"    ⚠ Error collecting groups: {e} (continuing)")
            all_groups = []
        
        # NOTE: We no longer collect every managed policy in the account.
        # We'll only collect policies that are attached to users/roles/groups
        # (and permission boundaries) after we enumerate those entities.
        all_policies = []
        
        try:
            service_linked_roles = collect_service_linked_roles(iam_client, None)
        except Exception as e:
            print(f"    ⚠ Error collecting service-linked roles: {e} (continuing)")
            service_linked_roles = []
        
        try:
            password_policy = collect_account_password_policy(iam_client, None)
        except Exception as e:
            print(f"    ⚠ Error collecting password policy: {e} (continuing)")
            password_policy = None
        
        try:
            account_summary = collect_account_summary(iam_client, None)
        except Exception as e:
            print(f"    ⚠ Error collecting account summary: {e} (continuing)")
            account_summary = None
        
        try:
            credential_report = collect_credential_report(iam_client, None)
        except Exception as e:
            print(f"    ⚠ Error collecting credential report: {e} (continuing)")
            credential_report = None
        
        # Add to combined structure
        all_data["all_users"] = all_users
        all_data["all_roles"] = all_roles
        all_data["all_groups"] = all_groups
        # placeholder; filled later with attached-only managed policies
        all_data["all_policies"] = all_policies
        all_data["service_linked_roles"] = service_linked_roles
        all_data["account_password_policy"] = password_policy
        all_data["account_summary"] = account_summary
        all_data["credential_report"] = credential_report
        
        # Generate master index
        try:
            master_index = generate_master_index(None, all_users, all_roles, all_groups, all_policies)
            all_data["master_index"] = master_index
        except Exception as e:
            print(f"    ⚠ Error generating master index: {e} (continuing)")
            all_data["master_index"] = {"error": str(e)}
        
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
                try:
                    # Collect user data but don't save individual files
                    from ventra.collector.resources.iam.users import (
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
                except Exception as e:
                    print(f"      ⚠ Error collecting details for user {username}: {e} (continuing)")
                    all_data["users_detail"][username] = {"error": str(e)}
        
        # Collect all roles
        all_data["roles_detail"] = {}
        if all_roles:
            print(f"[+] Collecting detailed information for {len(all_roles)} role(s)...\n")
            for idx, role in enumerate(all_roles, 1):
                role_name = role.get("RoleName")
                print(f"[{idx}/{len(all_roles)}] Processing role: {role_name}")
                try:
                    from ventra.collector.resources.iam.roles import (
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
                except Exception as e:
                    print(f"      ⚠ Error collecting details for role {role_name}: {e} (continuing)")
                    all_data["roles_detail"][role_name] = {"error": str(e)}
        
        # Collect all groups
        all_data["groups_detail"] = {}
        if all_groups:
            print(f"[+] Collecting detailed information for {len(all_groups)} group(s)...\n")
            for idx, group in enumerate(all_groups, 1):
                group_name = group.get("GroupName")
                print(f"[{idx}/{len(all_groups)}] Processing group: {group_name}")
                try:
                    from ventra.collector.resources.iam.groups import (
                        collect_group_metadata, collect_group_inline_policies,
                        collect_group_attached_policies
                    )
                    group_detail = {
                        "group": collect_group_metadata(iam_client, group_name, None),
                        "inline_policies": collect_group_inline_policies(iam_client, group_name, None),
                        "attached_policies": collect_group_attached_policies(iam_client, group_name, None),
                    }
                    all_data["groups_detail"][group_name] = group_detail
                except Exception as e:
                    print(f"      ⚠ Error collecting details for group {group_name}: {e} (continuing)")
                    all_data["groups_detail"][group_name] = {"error": str(e)}
        
        # Collect only ATTACHED managed policies (users/roles/groups + permission boundaries)
        attached_policy_arns = set()

        # Attached managed policies
        for user_detail in all_data.get("users_detail", {}).values():
            for p in (user_detail.get("attached_policies") or []):
                arn = p.get("PolicyArn")
                if arn:
                    attached_policy_arns.add(arn)
            pb_arn = _permissions_boundary_arn((user_detail.get("user") or {}).get("PermissionsBoundary"))
            if pb_arn:
                attached_policy_arns.add(pb_arn)

        for role_detail in all_data.get("roles_detail", {}).values():
            for p in (role_detail.get("attached_policies") or []):
                arn = p.get("PolicyArn")
                if arn:
                    attached_policy_arns.add(arn)
            pb_arn = _permissions_boundary_arn((role_detail.get("role") or {}).get("PermissionsBoundary"))
            if pb_arn:
                attached_policy_arns.add(pb_arn)

        for group_detail in all_data.get("groups_detail", {}).values():
            for p in (group_detail.get("attached_policies") or []):
                arn = p.get("PolicyArn")
                if arn:
                    attached_policy_arns.add(arn)

        attached_policy_arns = sorted(attached_policy_arns)
        all_data["attached_managed_policy_arns"] = attached_policy_arns
        all_data["attached_managed_policy_count"] = len(attached_policy_arns)

        # Update master index counts to reflect attached-only policies (best-effort)
        try:
            if isinstance(all_data.get("master_index"), dict) and "Summary" in all_data["master_index"]:
                all_data["master_index"]["Summary"]["TotalPolicies"] = len(attached_policy_arns)
        except Exception:
            pass

        all_data["policies_detail"] = {}
        if attached_policy_arns:
            print(f"[+] Collecting detailed information for {len(attached_policy_arns)} attached managed policy/policies...\n")
            from ventra.collector.resources.iam.policies import collect_policy_metadata, collect_policy_versions

            for idx, policy_arn in enumerate(attached_policy_arns, 1):
                policy_name = policy_arn.split("/")[-1] if "/" in policy_arn else policy_arn.split(":")[-1]
                print(f"[{idx}/{len(attached_policy_arns)}] Processing policy: {policy_arn}")
                try:
                    policy_detail = {
                        "policy": collect_policy_metadata(iam_client, policy_arn, None),
                        "policy_versions": collect_policy_versions(iam_client, policy_arn, None),
                    }
                    all_data["policies_detail"][policy_name] = policy_detail
                except Exception as e:
                    print(f"      ⚠ Error collecting details for policy {policy_arn}: {e} (continuing)")
                    all_data["policies_detail"][policy_name] = {"error": str(e)}
        
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
