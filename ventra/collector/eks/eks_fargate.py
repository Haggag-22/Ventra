"""
EKS Fargate Profiles Collector
Collects Fargate profiles for a cluster.
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


def run_eks_fargate(args):
    """Collect EKS Fargate profiles."""
    cluster_name = args.cluster
    print(f"[+] EKS Fargate Profiles Collector")
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
    except Exception as e:
        print(f"❌ Error getting EKS client: {e}")
        return
    
    try:
        fargate_data = {
            "cluster": cluster_name,
            "fargate_profiles": [],
        }
        
        print("[+] Listing Fargate profiles...")
        paginator = eks_client.get_paginator("list_fargate_profiles")
        profile_names = []
        for page in paginator.paginate(clusterName=cluster_name):
            profile_names.extend(page.get("fargateProfileNames", []))
        
        if not profile_names:
            print("    ⚠ No Fargate profiles found")
            fargate_data["message"] = "No Fargate profiles configured"
        else:
            print(f"    ✓ Found {len(profile_names)} Fargate profile(s)")
            
            # Get detailed information for each profile
            for profile_name in profile_names:
                print(f"[+] Collecting details for profile: {profile_name}")
                try:
                    profile_response = eks_client.describe_fargate_profile(
                        clusterName=cluster_name,
                        fargateProfileName=profile_name
                    )
                    profile = profile_response.get("fargateProfile", {})
                    
                    profile_info = {
                        "FargateProfileName": profile.get("fargateProfileName"),
                        "FargateProfileArn": profile.get("fargateProfileArn"),
                        "ClusterName": profile.get("clusterName"),
                        "CreatedAt": str(profile.get("createdAt", "")),
                        "PodExecutionRoleArn": profile.get("podExecutionRoleArn"),
                        "Subnets": profile.get("subnets", []),
                        "Selectors": profile.get("selectors", []),
                        "Status": profile.get("status"),
                        "Tags": profile.get("tags", {}),
                    }
                    
                    fargate_data["fargate_profiles"].append(profile_info)
                    
                except ClientError as e:
                    print(f"      ⚠ Error getting profile details: {e}")
        
        fargate_data["total_profiles"] = len(fargate_data["fargate_profiles"])
        
        # Save single combined file
        safe_name = cluster_name.replace(":", "_").replace("/", "_")
        filename = f"eks_fargate_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, fargate_data)
        if filepath:
            print(f"\n[✓] Saved Fargate profiles → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

