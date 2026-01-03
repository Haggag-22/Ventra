"""
ELB Listeners Collector
Collects load balancer listeners.
Attackers modify listeners to forward traffic to their own servers, disable health checks, or attach malicious target groups.
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


def run_elb_listeners(args):
    """Collect ELB listeners."""
    print(f"[+] ELB Listeners Collector")
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
        elb_client = _get_elb_client(args.region)
    except Exception as e:
        print(f"❌ Error getting ELB client: {e}")
        return
    
    try:
        listeners_data = {
            "load_balancers_v2": [],  # ALB/NLB
            "load_balancers_v1": [],  # Classic
        }
        
        # Collect ALB/NLB listeners
        print("[+] Listing Application/Network Load Balancers...")
        paginator = elbv2_client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_arn = lb.get("LoadBalancerArn")
                lb_name = lb.get("LoadBalancerName")
                
                print(f"[+] Collecting listeners for {lb_name} ({lb.get('Type')})")
                
                lb_info = {
                    "LoadBalancerArn": lb_arn,
                    "LoadBalancerName": lb_name,
                    "Type": lb.get("Type"),
                    "Scheme": lb.get("Scheme"),
                    "State": lb.get("State", {}),
                    "CreatedTime": str(lb.get("CreatedTime", "")),
                    "Listeners": [],
                }
                
                # Get listeners
                try:
                    listeners_paginator = elbv2_client.get_paginator("describe_listeners")
                    for listeners_page in listeners_paginator.paginate(LoadBalancerArn=lb_arn):
                        for listener in listeners_page.get("Listeners", []):
                            listener_info = {
                                "ListenerArn": listener.get("ListenerArn"),
                                "Port": listener.get("Port"),
                                "Protocol": listener.get("Protocol"),
                                "DefaultActions": listener.get("DefaultActions", []),
                                "Certificates": listener.get("Certificates", []),
                                "SslPolicy": listener.get("SslPolicy"),
                                "AlpnPolicy": listener.get("AlpnPolicy", []),
                            }
                            lb_info["Listeners"].append(listener_info)
                except ClientError as e:
                    print(f"      ⚠ Error getting listeners: {e}")
                
                listeners_data["load_balancers_v2"].append(lb_info)
                print(f"    ✓ Found {len(lb_info['Listeners'])} listener(s)")
        
        # Collect Classic ELB listeners
        print("[+] Listing Classic Load Balancers...")
        try:
            classic_lbs = elb_client.describe_load_balancers()
            for lb in classic_lbs.get("LoadBalancerDescriptions", []):
                lb_name = lb.get("LoadBalancerName")
                
                print(f"[+] Collecting listeners for Classic LB: {lb_name}")
                
                lb_info = {
                    "LoadBalancerName": lb_name,
                    "DNSName": lb.get("DNSName"),
                    "Scheme": lb.get("Scheme"),
                    "CreatedTime": str(lb.get("CreatedTime", "")),
                    "ListenerDescriptions": lb.get("ListenerDescriptions", []),
                    "Subnets": lb.get("Subnets", []),
                    "SecurityGroups": lb.get("SecurityGroups", []),
                    "HealthCheck": lb.get("HealthCheck", {}),
                }
                
                listeners_data["load_balancers_v1"].append(lb_info)
                print(f"    ✓ Found {len(lb_info['ListenerDescriptions'])} listener(s)")
        except ClientError as e:
            print(f"    ⚠ Error listing classic load balancers: {e}")
        
        listeners_data["total_alb_nlb"] = len(listeners_data["load_balancers_v2"])
        listeners_data["total_classic"] = len(listeners_data["load_balancers_v1"])
        
        print(f"\n    Summary: {listeners_data['total_alb_nlb']} ALB/NLB(s), {listeners_data['total_classic']} Classic ELB(s)")
        
        # Save single combined file
        filename = "elb_listeners.json"
        filepath = _save_json_file(output_dir, filename, listeners_data)
        if filepath:
            print(f"\n[✓] Saved listeners → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

