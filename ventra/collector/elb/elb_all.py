"""
ELB All Collector
Collects all ELB information (load balancers, listeners, target groups, access logs) into a single combined file.
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


def run_elb_all(args):
    """Collect all ELB data into a single file."""
    print(f"[+] ELB All Collector")
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
        print(f"❌ Error getting ELB clients: {e}")
        return
    
    try:
        all_data = {
            "LoadBalancersV2": [],  # ALB/NLB
            "LoadBalancersV1": [],  # Classic
            "TargetGroups": [],
        }
        
        # Collect ALB/NLB load balancers with listeners and access logs
        print("[+] Collecting ALB/NLB load balancers...")
        try:
            paginator = elbv2_client.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_arn = lb.get("LoadBalancerArn")
                    lb_name = lb.get("LoadBalancerName")
                    
                    print(f"[+] Collecting all data for {lb_name} ({lb.get('Type')})")
                    
                    lb_info = {
                        "LoadBalancerArn": lb_arn,
                        "LoadBalancerName": lb_name,
                        "Type": lb.get("Type"),
                        "Scheme": lb.get("Scheme"),
                        "State": lb.get("State", {}),
                        "CreatedTime": str(lb.get("CreatedTime", "")),
                        "DNSName": lb.get("DNSName"),
                        "CanonicalHostedZoneId": lb.get("CanonicalHostedZoneId"),
                        "VpcId": lb.get("VpcId"),
                        "AvailabilityZones": lb.get("AvailabilityZones", []),
                        "SecurityGroups": lb.get("SecurityGroups", []),
                        "IpAddressType": lb.get("IpAddressType"),
                        "CustomerOwnedIpv4Pool": lb.get("CustomerOwnedIpv4Pool"),
                        "Listeners": [],
                        "AccessLogs": None,
                    }
                    
                    # Get listeners
                    print(f"    → Collecting listeners...")
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
                        print(f"      ✓ Found {len(lb_info['Listeners'])} listener(s)")
                    except Exception as e:
                        print(f"      ⚠ Error getting listeners: {e} (continuing)")
                    
                    # Get access logs configuration
                    print(f"    → Collecting access logs configuration...")
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
                        print(f"      ✓ Collected access logs config")
                    except Exception as e:
                        print(f"      ⚠ Error getting access logs: {e} (continuing)")
                    
                    all_data["LoadBalancersV2"].append(lb_info)
                    print()
        except Exception as e:
            print(f"    ⚠ Error collecting ALB/NLB load balancers: {e} (continuing)")
        
        # Collect Classic ELB load balancers with listeners and access logs
        print("[+] Collecting Classic ELB load balancers...")
        try:
            classic_lbs = elb_client.describe_load_balancers()
            for lb in classic_lbs.get("LoadBalancerDescriptions", []):
                lb_name = lb.get("LoadBalancerName")
                
                print(f"[+] Collecting all data for Classic LB: {lb_name}")
                
                lb_info = {
                    "LoadBalancerName": lb_name,
                    "DNSName": lb.get("DNSName"),
                    "Scheme": lb.get("Scheme"),
                    "CreatedTime": str(lb.get("CreatedTime", "")),
                    "Subnets": lb.get("Subnets", []),
                    "SecurityGroups": lb.get("SecurityGroups", []),
                    "HealthCheck": lb.get("HealthCheck", {}),
                    "ListenerDescriptions": lb.get("ListenerDescriptions", []),
                    "AccessLogs": None,
                }
                
                # Get access logs configuration
                print(f"    → Collecting access logs configuration...")
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
                    print(f"      ✓ Collected access logs config")
                except Exception as e:
                    print(f"      ⚠ Error getting access logs: {e} (continuing)")
                
                all_data["LoadBalancersV1"].append(lb_info)
                print()
        except Exception as e:
            print(f"    ⚠ Error collecting Classic load balancers: {e} (continuing)")
        
        # Collect all target groups
        print("[+] Collecting target groups...")
        try:
            paginator = elbv2_client.get_paginator("describe_target_groups")
            for page in paginator.paginate():
                for tg in page.get("TargetGroups", []):
                    tg_arn = tg.get("TargetGroupArn")
                    tg_name = tg.get("TargetGroupName")
                    
                    print(f"[+] Collecting target group: {tg_name}")
                    
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
                        "Targets": [],
                        "Attributes": {},
                    }
                    
                    # Get targets and their health
                    try:
                        targets_response = elbv2_client.describe_target_health(TargetGroupArn=tg_arn)
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
                    except Exception as e:
                        print(f"    ⚠ Error getting targets: {e} (continuing)")
                    
                    # Get target group attributes
                    try:
                        attrs_response = elbv2_client.describe_target_group_attributes(TargetGroupArn=tg_arn)
                        tg_info["Attributes"] = {attr["Key"]: attr["Value"] for attr in attrs_response.get("Attributes", [])}
                    except Exception as e:
                        print(f"    ⚠ Error getting attributes: {e} (continuing)")
                    
                    all_data["TargetGroups"].append(tg_info)
        except Exception as e:
            print(f"    ⚠ Error collecting target groups: {e} (continuing)")
        
        all_data["total_alb_nlb"] = len(all_data["LoadBalancersV2"])
        all_data["total_classic"] = len(all_data["LoadBalancersV1"])
        all_data["total_target_groups"] = len(all_data["TargetGroups"])
        
        print(f"\n    Summary:")
        print(f"      ALB/NLB: {all_data['total_alb_nlb']}")
        print(f"      Classic: {all_data['total_classic']}")
        print(f"      Target Groups: {all_data['total_target_groups']}")
        
        # Save combined file
        filename = "elb_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all ELB data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

