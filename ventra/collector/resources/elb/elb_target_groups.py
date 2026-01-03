"""
ELB Target Groups Collector
Collects target groups and their health status.
Attackers attach malicious target groups to redirect traffic.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_elbv2_client(region):
    """ELB v2 (ALB/NLB) client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("elbv2")


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


def run_elb_target_groups(args):
    """Collect ELB target groups."""
    print(f"[+] ELB Target Groups Collector")
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
        elbv2_client = _get_elbv2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting ELB client: {e}")
        return
    
    try:
        target_groups_data = {
            "target_groups": [],
        }
        
        print("[+] Listing all target groups...")
        paginator = elbv2_client.get_paginator("describe_target_groups")
        for page in paginator.paginate():
            for tg in page.get("TargetGroups", []):
                tg_arn = tg.get("TargetGroupArn")
                tg_name = tg.get("TargetGroupName")
                
                print(f"[+] Collecting details for target group: {tg_name}")
                
                tg_info = {
                    "TargetGroupArn": tg_arn,
                    "TargetGroupName": tg_name,
                    "Protocol": tg.get("Protocol"),
                    "Port": tg.get("Port"),
                    "VpcId": tg.get("VpcId"),
                    "HealthCheckProtocol": tg.get("HealthCheckProtocol"),
                    "HealthCheckPort": tg.get("HealthCheckPort"),
                    "HealthCheckPath": tg.get("HealthCheckPath"),
                    "HealthCheckIntervalSeconds": tg.get("HealthCheckIntervalSeconds"),
                    "HealthCheckTimeoutSeconds": tg.get("HealthCheckTimeoutSeconds"),
                    "HealthyThresholdCount": tg.get("HealthyThresholdCount"),
                    "UnhealthyThresholdCount": tg.get("UnhealthyThresholdCount"),
                    "Matcher": tg.get("Matcher", {}),
                    "LoadBalancerArns": tg.get("LoadBalancerArns", []),
                    "TargetType": tg.get("TargetType"),
                    "ProtocolVersion": tg.get("ProtocolVersion"),
                    "IpAddressType": tg.get("IpAddressType"),
                }
                
                # Get targets and their health
                try:
                    targets_response = elbv2_client.describe_target_health(TargetGroupArn=tg_arn)
                    tg_info["Targets"] = []
                    for target in targets_response.get("TargetHealthDescriptions", []):
                        target_info = {
                            "Target": target.get("Target", {}),
                            "HealthCheckPort": target.get("HealthCheckPort"),
                            "TargetHealth": {
                                "State": target.get("TargetHealth", {}).get("State"),
                                "Reason": target.get("TargetHealth", {}).get("Reason"),
                                "Description": target.get("TargetHealth", {}).get("Description"),
                            },
                        }
                        tg_info["Targets"].append(target_info)
                    
                    print(f"    ✓ Found {len(tg_info['Targets'])} target(s)")
                except ClientError as e:
                    print(f"      ⚠ Error getting targets: {e}")
                    tg_info["Targets"] = []
                
                # Get target group attributes
                try:
                    attrs_response = elbv2_client.describe_target_group_attributes(TargetGroupArn=tg_arn)
                    tg_info["Attributes"] = {attr["Key"]: attr["Value"] for attr in attrs_response.get("Attributes", [])}
                except ClientError as e:
                    print(f"      ⚠ Error getting attributes: {e}")
                    tg_info["Attributes"] = {}
                
                target_groups_data["target_groups"].append(tg_info)
        
        target_groups_data["total_target_groups"] = len(target_groups_data["target_groups"])
        print(f"\n    Summary: {target_groups_data['total_target_groups']} target group(s)")
        
        # Save single combined file
        filename = "elb_target_groups.json"
        filepath = _save_json_file(output_dir, filename, target_groups_data)
        if filepath:
            print(f"\n[✓] Saved target groups → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

