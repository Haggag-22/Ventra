"""
EKS Addons Collector
Collects EKS addons for a cluster.
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


def run_eks_addons(args):
    """Collect EKS addons."""
    cluster_name = args.cluster
    print(f"[+] EKS Addons Collector")
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
        addons_data = {
            "cluster": cluster_name,
            "addons": [],
        }
        
        print("[+] Listing addons...")
        paginator = eks_client.get_paginator("list_addons")
        addon_names = []
        for page in paginator.paginate(clusterName=cluster_name):
            addon_names.extend(page.get("addons", []))
        
        if not addon_names:
            print("    ⚠ No addons found")
            addons_data["message"] = "No addons configured"
        else:
            print(f"    ✓ Found {len(addon_names)} addon(s)")
            
            # Get detailed information for each addon
            for addon_name in addon_names:
                print(f"[+] Collecting details for addon: {addon_name}")
                try:
                    addon_response = eks_client.describe_addon(
                        clusterName=cluster_name,
                        addonName=addon_name
                    )
                    addon = addon_response.get("addon", {})
                    
                    addon_info = {
                        "AddonName": addon.get("addonName"),
                        "ClusterName": addon.get("clusterName"),
                        "Status": addon.get("status"),
                        "AddonVersion": addon.get("addonVersion"),
                        "Health": addon.get("health", {}),
                        "AddonArn": addon.get("addonArn"),
                        "CreatedAt": str(addon.get("createdAt", "")),
                        "ModifiedAt": str(addon.get("modifiedAt", "")),
                        "ServiceAccountRoleArn": addon.get("serviceAccountRoleArn"),
                        "Tags": addon.get("tags", {}),
                        "Publisher": addon.get("publisher"),
                        "Owner": addon.get("owner"),
                        "MarketplaceInformation": addon.get("marketplaceInformation", {}),
                        "ConfigurationValues": addon.get("configurationValues"),
                    }
                    
                    addons_data["addons"].append(addon_info)
                    
                except ClientError as e:
                    print(f"      ⚠ Error getting addon details: {e}")
        
        addons_data["total_addons"] = len(addons_data["addons"])
        
        # Save single combined file
        safe_name = cluster_name.replace(":", "_").replace("/", "_")
        filename = f"eks_addons_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, addons_data)
        if filepath:
            print(f"\n[✓] Saved addons → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

