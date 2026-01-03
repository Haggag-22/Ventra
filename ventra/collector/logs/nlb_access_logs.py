"""
NLB (Network Load Balancer) Access Logs Collector
Collects access log configuration and events for NLBs.
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


def run_nlb_access_logs(args):
    """Collect NLB access log configurations."""
    print(f"[+] NLB Access Logs Collector")
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
    
    try:
        elbv2_client = _get_elbv2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting ELB v2 client: {e}")
        return
    
    try:
        print("[+] Describing NLBs...")
        paginator = elbv2_client.get_paginator("describe_load_balancers")
        all_load_balancers = []
        
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                # Filter for NLBs only (Type == 'network')
                if lb.get("Type") == "network":
                    all_load_balancers.append(lb)
        
        if not all_load_balancers:
            print("    ⚠ No NLBs found in this region")
            return
        
        print(f"    ✓ Found {len(all_load_balancers)} NLB(s)")
        
        nlb_data = []
        for lb in all_load_balancers:
            lb_arn = lb.get("LoadBalancerArn")
            lb_name = lb.get("LoadBalancerName")
            
            print(f"    Processing: {lb_name}")
            
            nlb_info = {
                "LoadBalancerArn": lb_arn,
                "LoadBalancerName": lb_name,
                "DNSName": lb.get("DNSName"),
                "State": lb.get("State"),
                "Type": lb.get("Type"),
                "Scheme": lb.get("Scheme"),
                "VpcId": lb.get("VpcId"),
                "Subnets": lb.get("Subnets", []),
                "CreatedTime": str(lb.get("CreatedTime", "")),
            }
            
            # Get access log attributes
            try:
                attributes_response = elbv2_client.describe_load_balancer_attributes(
                    LoadBalancerArn=lb_arn
                )
                attributes = {
                    attr.get("Key"): attr.get("Value")
                    for attr in attributes_response.get("Attributes", [])
                }
                nlb_info["Attributes"] = attributes
                
                # Extract access log configuration
                access_log_enabled = attributes.get("access_logs.s3.enabled", "false")
                access_log_bucket = attributes.get("access_logs.s3.bucket", "")
                access_log_prefix = attributes.get("access_logs.s3.prefix", "")
                
                nlb_info["AccessLogs"] = {
                    "Enabled": access_log_enabled == "true",
                    "S3Bucket": access_log_bucket,
                    "S3Prefix": access_log_prefix,
                }
                
                if access_log_enabled == "true":
                    print(f"      ✓ Access logs enabled: s3://{access_log_bucket}/{access_log_prefix}")
                else:
                    print(f"      ⚠ Access logs not enabled")
            except ClientError as e:
                print(f"      ⚠ Error getting attributes: {e}")
                nlb_info["Attributes"] = {}
                nlb_info["AccessLogs"] = {"Enabled": False}
            
            nlb_data.append(nlb_info)
        
        # Save to file
        filename = "nlb_access_logs.json"
        filepath = _save_json_file(output_dir, filename, {
            "load_balancers": nlb_data,
            "total": len(nlb_data)
        })
        
        if filepath:
            print(f"\n[✓] Saved NLB access log configurations → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")



