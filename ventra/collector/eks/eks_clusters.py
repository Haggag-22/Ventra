"""
EKS Clusters Collector
Collects EKS cluster metadata.
Huge attack surface - important for cloud security.
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


def run_eks_clusters(args):
    """Collect EKS clusters."""
    print(f"[+] EKS Clusters Collector")
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
        clusters_data = {
            "clusters": [],
        }
        
        print("[+] Listing all EKS clusters...")
        paginator = eks_client.get_paginator("list_clusters")
        cluster_names = []
        for page in paginator.paginate():
            cluster_names.extend(page.get("clusters", []))
        
        print(f"    ✓ Found {len(cluster_names)} cluster(s)")
        
        # Get detailed information for each cluster
        for cluster_name in cluster_names:
            print(f"[+] Collecting details for cluster: {cluster_name}")
            try:
                cluster_response = eks_client.describe_cluster(name=cluster_name)
                cluster = cluster_response.get("cluster", {})
                
                cluster_info = {
                    "Name": cluster.get("name"),
                    "Arn": cluster.get("arn"),
                    "CreatedAt": str(cluster.get("createdAt", "")),
                    "Version": cluster.get("version"),
                    "Endpoint": cluster.get("endpoint"),
                    "RoleArn": cluster.get("roleArn"),
                    "ResourcesVpcConfig": cluster.get("resourcesVpcConfig", {}),
                    "KubernetesNetworkConfig": cluster.get("kubernetesNetworkConfig", {}),
                    "Logging": cluster.get("logging", {}),
                    "Identity": cluster.get("identity", {}),
                    "Status": cluster.get("status"),
                    "CertificateAuthority": cluster.get("certificateAuthority", {}),
                    "ClientRequestToken": cluster.get("clientRequestToken"),
                    "PlatformVersion": cluster.get("platformVersion"),
                    "Tags": cluster.get("tags", {}),
                    "EncryptionConfig": cluster.get("encryptionConfig", []),
                    "ConnectorConfig": cluster.get("connectorConfig", {}),
                    "Id": cluster.get("id"),
                    "Health": cluster.get("health", {}),
                    "OutpostConfig": cluster.get("outpostConfig", {}),
                    "AccessConfig": cluster.get("accessConfig", {}),
                }
                
                clusters_data["clusters"].append(cluster_info)
                
            except ClientError as e:
                print(f"      ⚠ Error getting cluster details: {e}")
        
        clusters_data["total_clusters"] = len(clusters_data["clusters"])
        
        # Save single combined file
        filename = "eks_clusters.json"
        filepath = _save_json_file(output_dir, filename, clusters_data)
        if filepath:
            print(f"\n[✓] Saved clusters → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

