"""
EKS OIDC Collector
Collects OIDC identity provider configuration for a cluster.
Important for IAM roles for service accounts (IRSA).
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_eks_client(region):
    """EKS client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("eks")


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


def run_eks_oidc(args):
    """Collect EKS OIDC configuration."""
    cluster_name = args.cluster
    print(f"[+] EKS OIDC Collector")
    print(f"    Cluster:     {cluster_name}")
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
        eks_client = _get_eks_client(args.region)
        iam_client = _get_iam_client(args.region)
    except Exception as e:
        print(f"❌ Error getting clients: {e}")
        return
    
    try:
        oidc_data = {
            "cluster": cluster_name,
            "oidc_identity_provider": None,
            "iam_roles_for_service_accounts": [],
        }
        
        print("[+] Getting cluster identity configuration...")
        try:
            cluster_response = eks_client.describe_cluster(name=cluster_name)
            cluster = cluster_response.get("cluster", {})
            identity = cluster.get("identity", {})
            oidc = identity.get("oidc", {})
            
            oidc_data["oidc_identity_provider"] = {
                "Issuer": oidc.get("issuer"),
            }
            
            # Extract OIDC provider ARN from issuer
            issuer = oidc.get("issuer", "")
            if issuer:
                # Format: https://oidc.eks.region.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D304
                # Extract the ID
                oidc_id = issuer.split("/")[-1] if "/" in issuer else None
                
                if oidc_id:
                    # Try to find IAM OIDC provider
                    try:
                        oidc_providers = iam_client.list_open_id_connect_providers()
                        for provider_arn in oidc_providers.get("OpenIDConnectProviderList", []):
                            try:
                                provider = iam_client.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
                                provider_url = provider.get("Url", "")
                                if oidc_id in provider_arn or issuer in provider_url:
                                    oidc_data["oidc_identity_provider"]["ProviderArn"] = provider_arn
                                    oidc_data["oidc_identity_provider"]["ClientIDList"] = provider.get("ClientIDList", [])
                                    oidc_data["oidc_identity_provider"]["ThumbprintList"] = provider.get("ThumbprintList", [])
                                    oidc_data["oidc_identity_provider"]["CreateDate"] = str(provider.get("CreateDate", ""))
                                    oidc_data["oidc_identity_provider"]["Tags"] = provider.get("Tags", [])
                                    break
                            except ClientError:
                                pass
                    except ClientError as e:
                        print(f"      ⚠ Error listing OIDC providers: {e}")
                
                print(f"    ✓ OIDC issuer: {issuer}")
        except ClientError as e:
            print(f"    ❌ Error getting cluster identity: {e}")
            return
        
        # List IAM roles that might be used for service accounts
        print("[+] Searching for IAM roles with OIDC trust policy...")
        try:
            paginator = iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role.get("RoleName")
                    try:
                        role_response = iam_client.get_role(RoleName=role_name)
                        assume_role_policy = role_response.get("Role", {}).get("AssumeRolePolicyDocument", {})
                        
                        # Check if policy references the OIDC issuer
                        policy_str = json.dumps(assume_role_policy)
                        if issuer and issuer in policy_str:
                            oidc_data["iam_roles_for_service_accounts"].append({
                                "RoleName": role_name,
                                "RoleArn": role.get("Arn"),
                                "AssumeRolePolicyDocument": assume_role_policy,
                            })
                    except ClientError:
                        pass
        except ClientError as e:
            print(f"      ⚠ Error searching IAM roles: {e}")
        
        oidc_data["total_irsa_roles"] = len(oidc_data["iam_roles_for_service_accounts"])
        print(f"    ✓ Found {oidc_data['total_irsa_roles']} IAM role(s) for service accounts")
        
        # Save single combined file
        safe_name = cluster_name.replace(":", "_").replace("/", "_")
        filename = f"eks_oidc_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, oidc_data)
        if filepath:
            print(f"\n[✓] Saved OIDC config → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

