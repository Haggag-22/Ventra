"""
EKS Networking Collector
Collects networking configuration: VPC, subnets, security groups, etc.
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


def run_eks_networking(args):
    """Collect EKS networking configuration."""
    cluster_name = args.cluster
    print(f"[+] EKS Networking Collector")
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
        networking_data = {
            "cluster": cluster_name,
            "vpc_config": None,
            "kubernetes_network_config": None,
        }
        
        print("[+] Collecting networking configuration...")
        try:
            cluster_response = eks_client.describe_cluster(name=cluster_name)
            cluster = cluster_response.get("cluster", {})
            
            networking_data["vpc_config"] = cluster.get("resourcesVpcConfig", {})
            networking_data["kubernetes_network_config"] = cluster.get("kubernetesNetworkConfig", {})
            
            print(f"    ✓ Collected networking configuration")
        except ClientError as e:
            print(f"    ❌ Error getting cluster: {e}")
            return
        
        # Save single combined file
        safe_name = cluster_name.replace(":", "_").replace("/", "_")
        filename = f"eks_networking_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, networking_data)
        if filepath:
            print(f"\n[✓] Saved networking config → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

