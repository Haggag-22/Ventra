"""
EKS All Collector
Collects all EKS cluster information (cluster info, nodegroups, fargate, addons, security, logs, OIDC, networking) into a single combined file.
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


def run_eks_all(args):
    """Collect all EKS cluster data into a single file."""
    cluster_name = getattr(args, "cluster", None)
    
    if not cluster_name:
        print("❌ Error: --cluster parameter is required")
        print("   Usage: ventra collect eks all --case <case> --cluster <cluster_name>")
        return
    
    print(f"[+] EKS All Collector")
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
        # Collect all data
        all_data = {
            "ClusterName": cluster_name,
            "ClusterInfo": None,
            "Nodegroups": [],
            "FargateProfiles": [],
            "Addons": [],
            "Security": {},
            "LogsConfig": None,
            "OIDC": None,
            "Networking": {},
            "ControlPlaneLogs": None,
        }
        
        # 1. Get cluster info
        print(f"[+] Collecting cluster information...")
        try:
            cluster_response = eks_client.describe_cluster(name=cluster_name)
            cluster = cluster_response.get("cluster", {})
            all_data["ClusterInfo"] = {
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
                "Tags": cluster.get("tags", {}),
                "EncryptionConfig": cluster.get("encryptionConfig", []),
                "AccessConfig": cluster.get("accessConfig", {}),
                "Health": cluster.get("health", {}),
            }
            print(f"    ✓ Collected cluster info")
        except Exception as e:
            print(f"    ⚠ Error collecting cluster info: {e} (continuing)")
        
        # 2. Collect nodegroups
        print(f"[+] Collecting nodegroups...")
        try:
            paginator = eks_client.get_paginator("list_nodegroups")
            nodegroup_names = []
            for page in paginator.paginate(clusterName=cluster_name):
                nodegroup_names.extend(page.get("nodegroups", []))
            
            for nodegroup_name in nodegroup_names:
                try:
                    nodegroup_response = eks_client.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=nodegroup_name
                    )
                    nodegroup = nodegroup_response.get("nodegroup", {})
                    all_data["Nodegroups"].append({
                        "NodegroupName": nodegroup.get("nodegroupName"),
                        "Status": nodegroup.get("status"),
                        "Version": nodegroup.get("version"),
                        "InstanceTypes": nodegroup.get("instanceTypes", []),
                        "ScalingConfig": nodegroup.get("scalingConfig", {}),
                        "Subnets": nodegroup.get("subnets", []),
                        "NodeRole": nodegroup.get("nodeRole"),
                        "Tags": nodegroup.get("tags", {}),
                        "Health": nodegroup.get("health", {}),
                    })
                except Exception as e:
                    print(f"      ⚠ Error getting nodegroup {nodegroup_name}: {e} (continuing)")
            print(f"    ✓ Found {len(all_data['Nodegroups'])} nodegroup(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting nodegroups: {e} (continuing)")
        
        # 3. Collect Fargate profiles
        print(f"[+] Collecting Fargate profiles...")
        try:
            paginator = eks_client.get_paginator("list_fargate_profiles")
            profile_names = []
            for page in paginator.paginate(clusterName=cluster_name):
                profile_names.extend(page.get("fargateProfileNames", []))
            
            for profile_name in profile_names:
                try:
                    profile_response = eks_client.describe_fargate_profile(
                        clusterName=cluster_name,
                        fargateProfileName=profile_name
                    )
                    profile = profile_response.get("fargateProfile", {})
                    all_data["FargateProfiles"].append({
                        "FargateProfileName": profile.get("fargateProfileName"),
                        "Status": profile.get("status"),
                        "PodExecutionRoleArn": profile.get("podExecutionRoleArn"),
                        "Subnets": profile.get("subnets", []),
                        "Selectors": profile.get("selectors", []),
                        "Tags": profile.get("tags", {}),
                    })
                except Exception as e:
                    print(f"      ⚠ Error getting Fargate profile {profile_name}: {e} (continuing)")
            print(f"    ✓ Found {len(all_data['FargateProfiles'])} Fargate profile(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting Fargate profiles: {e} (continuing)")
        
        # 4. Collect addons
        print(f"[+] Collecting addons...")
        try:
            paginator = eks_client.get_paginator("list_addons")
            addon_names = []
            for page in paginator.paginate(clusterName=cluster_name):
                addon_names.extend(page.get("addons", []))
            
            for addon_name in addon_names:
                try:
                    addon_response = eks_client.describe_addon(
                        clusterName=cluster_name,
                        addonName=addon_name
                    )
                    addon = addon_response.get("addon", {})
                    all_data["Addons"].append({
                        "AddonName": addon.get("addonName"),
                        "Status": addon.get("status"),
                        "AddonVersion": addon.get("addonVersion"),
                        "Health": addon.get("health", {}),
                        "ServiceAccountRoleArn": addon.get("serviceAccountRoleArn"),
                        "Tags": addon.get("tags", {}),
                    })
                except Exception as e:
                    print(f"      ⚠ Error getting addon {addon_name}: {e} (continuing)")
            print(f"    ✓ Found {len(all_data['Addons'])} addon(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting addons: {e} (continuing)")
        
        # 5. Collect security config
        print(f"[+] Collecting security configuration...")
        try:
            if all_data["ClusterInfo"]:
                all_data["Security"] = {
                    "EncryptionConfig": all_data["ClusterInfo"].get("EncryptionConfig", []),
                    "KubernetesNetworkConfig": all_data["ClusterInfo"].get("KubernetesNetworkConfig", {}),
                    "AccessConfig": all_data["ClusterInfo"].get("AccessConfig", {}),
                    "ResourcesVpcConfig": all_data["ClusterInfo"].get("ResourcesVpcConfig", {}),
                }
                print(f"    ✓ Collected security config")
        except Exception as e:
            print(f"    ⚠ Error collecting security: {e} (continuing)")
        
        # 6. Collect logs config
        print(f"[+] Collecting logs configuration...")
        try:
            if all_data["ClusterInfo"]:
                all_data["LogsConfig"] = all_data["ClusterInfo"].get("Logging", {})
                print(f"    ✓ Collected logs config")
        except Exception as e:
            print(f"    ⚠ Error collecting logs config: {e} (continuing)")
        
        # 7. Collect OIDC identity provider
        print(f"[+] Collecting OIDC identity provider...")
        try:
            if all_data["ClusterInfo"]:
                identity = all_data["ClusterInfo"].get("Identity", {})
                oidc = identity.get("oidc", {})
                if oidc:
                    oidc_issuer = oidc.get("issuer", "")
                    if oidc_issuer:
                        all_data["OIDC"] = {
                            "Issuer": oidc_issuer,
                        }
                        # Try to get OIDC provider details
                        try:
                            # Extract account ID and provider ID from issuer
                            if "//" in oidc_issuer:
                                parts = oidc_issuer.split("//")[1].split(".")
                                if len(parts) >= 2:
                                    provider_id = parts[0]
                                    account_id = parts[1] if parts[1].isdigit() else ""
                                    if provider_id and account_id:
                                        provider_arn = f"arn:aws:iam::{account_id}:oidc-provider/{provider_id}"
                                        oidc_response = iam_client.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
                                        all_data["OIDC"]["Provider"] = oidc_response.get("Url", "")
                        except Exception:
                            pass
                        print(f"    ✓ Collected OIDC info")
        except Exception as e:
            print(f"    ⚠ Error collecting OIDC: {e} (continuing)")
        
        # 8. Collect networking
        print(f"[+] Collecting networking configuration...")
        try:
            if all_data["ClusterInfo"]:
                all_data["Networking"] = {
                    "ResourcesVpcConfig": all_data["ClusterInfo"].get("ResourcesVpcConfig", {}),
                    "KubernetesNetworkConfig": all_data["ClusterInfo"].get("KubernetesNetworkConfig", {}),
                }
                print(f"    ✓ Collected networking config")
        except Exception as e:
            print(f"    ⚠ Error collecting networking: {e} (continuing)")
        
        # 9. Control plane logs (from logging config)
        all_data["ControlPlaneLogs"] = all_data["LogsConfig"]
        
        # Save combined file
        safe_name = cluster_name.replace(":", "_").replace("/", "_").replace(" ", "_")
        filename = f"eks_{safe_name}_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all EKS data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
