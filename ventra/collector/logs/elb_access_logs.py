"""
ELB Access Logs Collector
Collects access log configuration for load balancers.
Access logs reveal traffic patterns and potential exfiltration.
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


def _get_elb_client(region):
    """ELB v1 (Classic) client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("elb")


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


def run_elb_access_logs(args):
    """Collect ELB access log configurations."""
    print(f"[+] ELB Access Logs Collector")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "logs")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        elbv2_client = _get_elbv2_client(args.region)
        elb_client = _get_elb_client(args.region)
    except Exception as e:
        print(f"❌ Error getting ELB client: {e}")
        return
    
    try:
        access_logs_data = {
            "load_balancers_v2": [],  # ALB/NLB
            "load_balancers_v1": [],  # Classic
        }
        
        # Collect ALB/NLB access log configs
        print("[+] Collecting access log configs for ALB/NLB...")
        paginator = elbv2_client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_arn = lb.get("LoadBalancerArn")
                lb_name = lb.get("LoadBalancerName")
                
                lb_info = {
                    "LoadBalancerArn": lb_arn,
                    "LoadBalancerName": lb_name,
                    "Type": lb.get("Type"),
                    "AccessLogs": None,
                }
                
                # Get attributes (includes access logs config)
                try:
                    attrs_response = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                    attrs = {attr["Key"]: attr["Value"] for attr in attrs_response.get("Attributes", [])}
                    
                    if attrs.get("access_logs.s3.enabled") == "true":
                        lb_info["AccessLogs"] = {
                            "Enabled": True,
                            "S3BucketName": attrs.get("access_logs.s3.bucket"),
                            "S3BucketPrefix": attrs.get("access_logs.s3.prefix"),
                        }
                    else:
                        lb_info["AccessLogs"] = {"Enabled": False}
                except ClientError as e:
                    print(f"      ⚠ Error getting attributes for {lb_name}: {e}")
                
                access_logs_data["load_balancers_v2"].append(lb_info)
        
        # Collect Classic ELB access log configs
        print("[+] Collecting access log configs for Classic ELB...")
        try:
            classic_lbs = elb_client.describe_load_balancers()
            for lb in classic_lbs.get("LoadBalancerDescriptions", []):
                lb_name = lb.get("LoadBalancerName")
                
                lb_info = {
                    "LoadBalancerName": lb_name,
                    "AccessLogs": None,
                }
                
                # Get attributes
                try:
                    attrs_response = elb_client.describe_load_balancer_attributes(LoadBalancerName=lb_name)
                    attrs = attrs_response.get("LoadBalancerAttributes", {})
                    access_logs = attrs.get("AccessLog", {})
                    
                    if access_logs.get("Enabled"):
                        lb_info["AccessLogs"] = {
                            "Enabled": True,
                            "S3BucketName": access_logs.get("S3BucketName"),
                            "S3BucketPrefix": access_logs.get("S3BucketPrefix"),
                            "EmitInterval": access_logs.get("EmitInterval"),
                        }
                    else:
                        lb_info["AccessLogs"] = {"Enabled": False}
                except ClientError as e:
                    print(f"      ⚠ Error getting attributes for {lb_name}: {e}")
                
                access_logs_data["load_balancers_v1"].append(lb_info)
        except ClientError as e:
            print(f"    ⚠ Error listing classic load balancers: {e}")
        
        access_logs_data["total_alb_nlb"] = len(access_logs_data["load_balancers_v2"])
        access_logs_data["total_classic"] = len(access_logs_data["load_balancers_v1"])
        
        # Count enabled access logs
        enabled_v2 = sum(1 for lb in access_logs_data["load_balancers_v2"] 
                        if lb.get("AccessLogs", {}).get("Enabled"))
        enabled_v1 = sum(1 for lb in access_logs_data["load_balancers_v1"] 
                        if lb.get("AccessLogs", {}).get("Enabled"))
        
        print(f"\n    Summary:")
        print(f"      ALB/NLB: {access_logs_data['total_alb_nlb']} total, {enabled_v2} with access logs enabled")
        print(f"      Classic: {access_logs_data['total_classic']} total, {enabled_v1} with access logs enabled")
        
        # Save single combined file
        filename = "elb_access_logs.json"
        filepath = _save_json_file(output_dir, filename, access_logs_data)
        if filepath:
            print(f"\n[✓] Saved access log configs → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

