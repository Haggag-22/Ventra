"""
IAM Users Collector
Collects comprehensive IAM user information.
"""
import os
import json
import boto3
import base64
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


def collect_user_identity(iam_client, username, output_dir):
    """Collect user identity metadata."""
    try:
        user_response = iam_client.get_user(UserName=username)
        user_data = {
            "UserName": user_response.get("User", {}).get("UserName"),
            "UserId": user_response.get("User", {}).get("UserId"),
            "Arn": user_response.get("User", {}).get("Arn"),
            "Path": user_response.get("User", {}).get("Path"),
            "CreateDate": str(user_response.get("User", {}).get("CreateDate", "")),
            "PasswordLastUsed": str(user_response.get("User", {}).get("PasswordLastUsed", "")) if user_response.get("User", {}).get("PasswordLastUsed") else None,
            "PermissionsBoundary": user_response.get("User", {}).get("PermissionsBoundary"),
            "Tags": user_response.get("User", {}).get("Tags", []),
        }
        if output_dir:
            _save_json_file(output_dir, "user.json", user_data)
        return user_data
    except ClientError as e:
        print(f"    ❌ Error getting user: {e}")
        return None


def collect_user_inline_policies(iam_client, username, output_dir):
    """Collect all inline policies for a user."""
    inline_policies = []
    try:
        paginator = iam_client.get_paginator("list_user_policies")
        for page in paginator.paginate(UserName=username):
            for policy_name in page.get("PolicyNames", []):
                try:
                    policy_response = iam_client.get_user_policy(
                        UserName=username,
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


def collect_user_attached_policies(iam_client, username, output_dir):
    """Collect all attached managed policies for a user."""
    attached_policies = []
    try:
        paginator = iam_client.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=username):
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


def collect_user_groups(iam_client, username, output_dir):
    """Collect all groups for a user."""
    groups = []
    try:
        paginator = iam_client.get_paginator("list_groups_for_user")
        for page in paginator.paginate(UserName=username):
            for group in page.get("Groups", []):
                groups.append({
                    "GroupName": group.get("GroupName"),
                    "GroupId": group.get("GroupId"),
                    "Arn": group.get("Arn"),
                    "Path": group.get("Path"),
                    "CreateDate": str(group.get("CreateDate", "")),
                })
    except ClientError as e:
        print(f"    ⚠ Error listing groups: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "groups.json", groups)
    return groups


def collect_user_access_keys(iam_client, username, output_dir):
    """Collect all access keys for a user."""
    access_keys = []
    try:
        paginator = iam_client.get_paginator("list_access_keys")
        for page in paginator.paginate(UserName=username):
            for key_metadata in page.get("AccessKeyMetadata", []):
                access_key_id = key_metadata.get("AccessKeyId")
                key_info = {
                    "AccessKeyId": access_key_id,
                    "Status": key_metadata.get("Status"),
                    "CreateDate": str(key_metadata.get("CreateDate", "")),
                }
                
                # Get last used information
                try:
                    last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    key_info["LastUsed"] = {
                        "LastUsedDate": str(last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate", "")),
                        "ServiceName": last_used.get("AccessKeyLastUsed", {}).get("ServiceName"),
                        "Region": last_used.get("AccessKeyLastUsed", {}).get("Region"),
                    }
                except ClientError:
                    pass
                
                access_keys.append(key_info)
    except ClientError as e:
        print(f"    ⚠ Error listing access keys: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "access_keys.json", access_keys)
    return access_keys


def collect_user_mfa_devices(iam_client, username, output_dir):
    """Collect MFA devices for a user."""
    mfa_devices = []
    try:
        paginator = iam_client.get_paginator("list_mfa_devices")
        for page in paginator.paginate(UserName=username):
            for device in page.get("MFADevices", []):
                mfa_devices.append({
                    "UserName": device.get("UserName"),
                    "SerialNumber": device.get("SerialNumber"),
                    "EnableDate": str(device.get("EnableDate", "")),
                })
    except ClientError as e:
        print(f"    ⚠ Error listing MFA devices: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "mfa_devices.json", mfa_devices)
    return mfa_devices


def collect_user_signing_certificates(iam_client, username, output_dir):
    """Collect signing certificates for a user."""
    signing_certs = []
    try:
        paginator = iam_client.get_paginator("list_signing_certificates")
        for page in paginator.paginate(UserName=username):
            for cert in page.get("Certificates", []):
                signing_certs.append({
                    "UserName": cert.get("UserName"),
                    "CertificateId": cert.get("CertificateId"),
                    "CertificateBody": cert.get("CertificateBody"),
                    "Status": cert.get("Status"),
                    "UploadDate": str(cert.get("UploadDate", "")),
                })
    except ClientError as e:
        print(f"    ⚠ Error listing signing certificates: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "signing_certificates.json", signing_certs)
    return signing_certs


def collect_user_ssh_public_keys(iam_client, username, output_dir):
    """Collect SSH public keys for a user."""
    ssh_keys = []
    try:
        paginator = iam_client.get_paginator("list_ssh_public_keys")
        for page in paginator.paginate(UserName=username):
            for key_metadata in page.get("SSHPublicKeys", []):
                ssh_key_id = key_metadata.get("SSHPublicKeyId")
                key_info = {
                    "UserName": key_metadata.get("UserName"),
                    "SSHPublicKeyId": ssh_key_id,
                    "Status": key_metadata.get("Status"),
                    "UploadDate": str(key_metadata.get("UploadDate", "")),
                }
                
                # Get the actual key
                try:
                    key_response = iam_client.get_ssh_public_key(
                        UserName=username,
                        SSHPublicKeyId=ssh_key_id,
                        Encoding="SSH"
                    )
                    key_info["SSHPublicKeyBody"] = key_response.get("SSHPublicKey", {}).get("SSHPublicKeyBody")
                except ClientError:
                    pass
                
                ssh_keys.append(key_info)
    except ClientError as e:
        print(f"    ⚠ Error listing SSH public keys: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "ssh_public_keys.json", ssh_keys)
    return ssh_keys


def collect_user_service_specific_credentials(iam_client, username, output_dir):
    """Collect service-specific credentials for a user."""
    service_creds = []
    try:
        # list_service_specific_credentials doesn't support pagination
        response = iam_client.list_service_specific_credentials(UserName=username)
        for cred in response.get("ServiceSpecificCredentials", []):
            service_creds.append({
                "UserName": cred.get("UserName"),
                "ServiceName": cred.get("ServiceName"),
                "ServiceUserName": cred.get("ServiceUserName"),
                "ServiceSpecificCredentialId": cred.get("ServiceSpecificCredentialId"),
                "Status": cred.get("Status"),
                "CreateDate": str(cred.get("CreateDate", "")),
            })
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchEntity":
            # User doesn't have service-specific credentials
            pass
        else:
            print(f"    ⚠ Error listing service-specific credentials: {e}")
    
    if output_dir:
        _save_json_file(output_dir, "service_specific_credentials.json", service_creds)
    return service_creds


def collect_user_login_profile(iam_client, username, output_dir):
    """Collect login profile information for a user."""
    login_profile = None
    try:
        profile_response = iam_client.get_login_profile(UserName=username)
        login_profile = {
            "UserName": profile_response.get("LoginProfile", {}).get("UserName"),
            "CreateDate": str(profile_response.get("LoginProfile", {}).get("CreateDate", "")),
            "PasswordResetRequired": profile_response.get("LoginProfile", {}).get("PasswordResetRequired", False),
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchEntity":
            # User doesn't have a login profile (console access disabled)
            login_profile = {"LoginProfile": None}
        else:
            print(f"    ⚠ Error getting login profile: {e}")
    
    if login_profile and output_dir:
        _save_json_file(output_dir, "login_profile.json", login_profile)
    return login_profile


def run_iam_user(args):
    """Collect comprehensive IAM information for a single user."""
    username = args.name
    print(f"[+] IAM User Collector")
    print(f"    User:        {username}")
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
        iam_client = _get_iam_client(args.region)
    except Exception as e:
        print(f"❌ Error getting IAM client: {e}")
        return
    
    try:
        # Collect all data into a single structure
        user_data = {}
        
        print(f"[+] Collecting user identity...")
        user_identity = collect_user_identity(iam_client, username, None)
        user_data["user"] = user_identity if user_identity else {}
        if user_identity:
            print(f"    ✓ Collected user identity")
        else:
            print(f"    ⚠ No user identity found (continuing with available data)")
        
        print(f"[+] Collecting inline policies...")
        inline_policies = collect_user_inline_policies(iam_client, username, None)
        user_data["inline_policies"] = inline_policies
        print(f"    ✓ Collected {len(inline_policies)} inline policy/policies")
        
        print(f"[+] Collecting attached managed policies...")
        attached_policies = collect_user_attached_policies(iam_client, username, None)
        user_data["attached_policies"] = attached_policies
        print(f"    ✓ Collected {len(attached_policies)} attached policy/policies")
        
        print(f"[+] Collecting group memberships...")
        groups = collect_user_groups(iam_client, username, None)
        user_data["groups"] = groups
        print(f"    ✓ Collected {len(groups)} group(s)")
        
        print(f"[+] Collecting access keys...")
        access_keys = collect_user_access_keys(iam_client, username, None)
        user_data["access_keys"] = access_keys
        print(f"    ✓ Collected {len(access_keys)} access key(s)")
        
        print(f"[+] Collecting MFA devices...")
        mfa_devices = collect_user_mfa_devices(iam_client, username, None)
        user_data["mfa_devices"] = mfa_devices
        print(f"    ✓ Collected {len(mfa_devices)} MFA device(s)")
        
        print(f"[+] Collecting signing certificates...")
        signing_certs = collect_user_signing_certificates(iam_client, username, None)
        user_data["signing_certificates"] = signing_certs
        print(f"    ✓ Collected {len(signing_certs)} signing certificate(s)")
        
        print(f"[+] Collecting SSH public keys...")
        ssh_keys = collect_user_ssh_public_keys(iam_client, username, None)
        user_data["ssh_public_keys"] = ssh_keys
        print(f"    ✓ Collected {len(ssh_keys)} SSH public key(s)")
        
        print(f"[+] Collecting service-specific credentials...")
        service_creds = collect_user_service_specific_credentials(iam_client, username, None)
        user_data["service_specific_credentials"] = service_creds
        print(f"    ✓ Collected {len(service_creds)} service-specific credential(s)")
        
        print(f"[+] Collecting login profile...")
        login_profile = collect_user_login_profile(iam_client, username, None)
        user_data["login_profile"] = login_profile
        if login_profile:
            print(f"    ✓ Collected login profile")
        else:
            print(f"    ⚠ No login profile (console access disabled)")
        
        # Save single combined file
        filename = f"user_{username}.json"
        filepath = _save_json_file(output_dir, filename, user_data)
        if filepath:
            print(f"\n[✓] Saved all user data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

