"""
EKS Nodegroups Collector
Collects EKS nodegroup configurations for a cluster.
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


def run_eks_nodegroups(args):
    """Collect EKS nodegroups."""
    cluster_name = args.cluster
    print(f"[+] EKS Nodegroups Collector")
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
        nodegroups_data = {
            "cluster": cluster_name,
            "nodegroups": [],
        }
        
        print("[+] Listing nodegroups...")
        paginator = eks_client.get_paginator("list_nodegroups")
        nodegroup_names = []
        for page in paginator.paginate(clusterName=cluster_name):
            nodegroup_names.extend(page.get("nodegroups", []))
        
        print(f"    ✓ Found {len(nodegroup_names)} nodegroup(s)")
        
        # Get detailed information for each nodegroup
        for nodegroup_name in nodegroup_names:
            print(f"[+] Collecting details for nodegroup: {nodegroup_name}")
            try:
                nodegroup_response = eks_client.describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup_name
                )
                nodegroup = nodegroup_response.get("nodegroup", {})
                
                nodegroup_info = {
                    "NodegroupName": nodegroup.get("nodegroupName"),
                    "NodegroupArn": nodegroup.get("nodegroupArn"),
                    "ClusterName": nodegroup.get("clusterName"),
                    "Version": nodegroup.get("version"),
                    "ReleaseVersion": nodegroup.get("releaseVersion"),
                    "CreatedAt": str(nodegroup.get("createdAt", "")),
                    "ModifiedAt": str(nodegroup.get("modifiedAt", "")),
                    "Status": nodegroup.get("status"),
                    "CapacityType": nodegroup.get("capacityType"),
                    "ScalingConfig": nodegroup.get("scalingConfig", {}),
                    "InstanceTypes": nodegroup.get("instanceTypes", []),
                    "Subnets": nodegroup.get("subnets", []),
                    "RemoteAccess": nodegroup.get("remoteAccess", {}),
                    "AmiType": nodegroup.get("amiType"),
                    "NodeRole": nodegroup.get("nodeRole"),
                    "Labels": nodegroup.get("labels", {}),
                    "Taints": nodegroup.get("taints", []),
                    "Resources": nodegroup.get("resources", {}),
                    "DiskSize": nodegroup.get("diskSize"),
                    "Health": nodegroup.get("health", {}),
                    "UpdateConfig": nodegroup.get("updateConfig", {}),
                    "LaunchTemplate": nodegroup.get("launchTemplate", {}),
                    "Tags": nodegroup.get("tags", {}),
                }
                
                nodegroups_data["nodegroups"].append(nodegroup_info)
                
            except ClientError as e:
                print(f"      ⚠ Error getting nodegroup details: {e}")
        
        nodegroups_data["total_nodegroups"] = len(nodegroups_data["nodegroups"])
        
        # Save single combined file
        safe_name = cluster_name.replace(":", "_").replace("/", "_")
        filename = f"eks_nodegroups_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, nodegroups_data)
        if filepath:
            print(f"\n[✓] Saved nodegroups → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

