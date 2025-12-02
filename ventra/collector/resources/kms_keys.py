"""
KMS Collector
Collects KMS keys, key policies, aliases, key usage, encryption context, and rotation status.
Important for data access analysis.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_kms_client(region):
    """KMS client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("kms")


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


def run_kms_keys(args):
    """Collect comprehensive KMS information."""
    print(f"[+] KMS Collector")
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
        kms_client = _get_kms_client(args.region)
    except Exception as e:
        print(f"❌ Error getting KMS client: {e}")
        return
    
    try:
        kms_data = {
            "keys": [],
            "aliases": [],
        }
        
        # List all keys
        print("[+] Listing all KMS keys...")
        paginator = kms_client.get_paginator("list_keys")
        key_ids = []
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                key_ids.append(key.get("KeyId"))
        
        print(f"    ✓ Found {len(key_ids)} key(s)")
        
        # Get detailed information for each key
        for key_id in key_ids:
            print(f"[+] Collecting details for key: {key_id}")
            try:
                # Describe key
                key_response = kms_client.describe_key(KeyId=key_id)
                key_metadata = key_response.get("KeyMetadata", {})
                
                key_info = {
                    "KeyId": key_metadata.get("KeyId"),
                    "Arn": key_metadata.get("Arn"),
                    "AWSAccountId": key_metadata.get("AWSAccountId"),
                    "CreationDate": str(key_metadata.get("CreationDate", "")),
                    "Enabled": key_metadata.get("Enabled"),
                    "Description": key_metadata.get("Description"),
                    "KeyUsage": key_metadata.get("KeyUsage"),
                    "KeyState": key_metadata.get("KeyState"),
                    "DeletionDate": str(key_metadata.get("DeletionDate", "")) if key_metadata.get("DeletionDate") else None,
                    "ValidTo": str(key_metadata.get("ValidTo", "")) if key_metadata.get("ValidTo") else None,
                    "Origin": key_metadata.get("Origin"),
                    "KeySpec": key_metadata.get("KeySpec"),
                    "KeyManager": key_metadata.get("KeyManager"),
                    "CustomerMasterKeySpec": key_metadata.get("CustomerMasterKeySpec"),
                    "EncryptionAlgorithms": key_metadata.get("EncryptionAlgorithms", []),
                    "SigningAlgorithms": key_metadata.get("SigningAlgorithms", []),
                }
                
                # Get key policy
                try:
                    policy_response = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
                    key_info["Policy"] = json.loads(policy_response.get("Policy", "{}"))
                except ClientError as e:
                    print(f"      ⚠ Error getting key policy: {e}")
                    key_info["Policy"] = None
                
                # Get key rotation status
                try:
                    rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
                    key_info["KeyRotationEnabled"] = rotation_response.get("KeyRotationEnabled", False)
                except ClientError as e:
                    print(f"      ⚠ Error getting rotation status: {e}")
                    key_info["KeyRotationEnabled"] = None
                
                # Get key usage (grants)
                try:
                    grants_paginator = kms_client.get_paginator("list_grants")
                    grants = []
                    for grants_page in grants_paginator.paginate(KeyId=key_id):
                        for grant in grants_page.get("Grants", []):
                            grants.append({
                                "GrantId": grant.get("GrantId"),
                                "GranteePrincipal": grant.get("GranteePrincipal"),
                                "RetiringPrincipal": grant.get("RetiringPrincipal"),
                                "Operations": grant.get("Operations", []),
                                "Constraints": grant.get("Constraints", {}),
                                "IssuingAccount": grant.get("IssuingAccount"),
                                "CreationDate": str(grant.get("CreationDate", "")),
                                "Name": grant.get("Name"),
                            })
                    key_info["Grants"] = grants
                except ClientError as e:
                    print(f"      ⚠ Error getting grants: {e}")
                    key_info["Grants"] = []
                
                # Get tags
                try:
                    tags_response = kms_client.list_resource_tags(KeyId=key_id)
                    key_info["Tags"] = {tag["TagKey"]: tag["TagValue"] 
                                       for tag in tags_response.get("Tags", [])}
                except ClientError as e:
                    print(f"      ⚠ Error getting tags: {e}")
                    key_info["Tags"] = {}
                
                kms_data["keys"].append(key_info)
                
            except ClientError as e:
                print(f"      ⚠ Error getting key details: {e}")
        
        # List all aliases
        print("[+] Listing all key aliases...")
        paginator = kms_client.get_paginator("list_aliases")
        for page in paginator.paginate():
            for alias in page.get("Aliases", []):
                alias_info = {
                    "AliasName": alias.get("AliasName"),
                    "AliasArn": alias.get("AliasArn"),
                    "TargetKeyId": alias.get("TargetKeyId"),
                    "CreationDate": str(alias.get("CreationDate", "")),
                    "LastUpdatedDate": str(alias.get("LastUpdatedDate", "")),
                }
                kms_data["aliases"].append(alias_info)
        
        kms_data["total_keys"] = len(kms_data["keys"])
        kms_data["total_aliases"] = len(kms_data["aliases"])
        
        print(f"    ✓ Collected {kms_data['total_keys']} key(s)")
        print(f"    ✓ Collected {kms_data['total_aliases']} alias(es)")
        
        # Save single combined file
        filename = "kms_keys.json"
        filepath = _save_json_file(output_dir, filename, kms_data)
        if filepath:
            print(f"\n[✓] Saved KMS data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

