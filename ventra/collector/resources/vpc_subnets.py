"""
VPC Collector Module
Collects comprehensive VPC network infrastructure metadata.
"""
import os
import json
import re
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_ec2_client(region):
    """EC2 client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("ec2")


def _get_cloudwatch_logs_client(region):
    """CloudWatch Logs client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("logs")


def _resolve_output_dir(args):
    """Resolve output directory - use case_dir if available, otherwise fallback."""
    # Use case_dir if available (set by CLI routing)
    if hasattr(args, "case_dir") and args.case_dir:
        output_base = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_base = args.output
    else:
        # Fallback to default output location
        output_base = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_base = os.path.join(output_base, "resources")
    os.makedirs(output_base, exist_ok=True)
    return output_base


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


def run_vpc_subnets(args):
    """Collect VPC subnet information (describe_subnets)."""
    print("[+] VPC Subnets Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing subnets...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_subnets(Filters=filters if filters else None)
        subnets = response.get("Subnets", [])
        
        if not subnets:
            print("    ⚠ No subnets found")
            return
        
        print(f"    ✓ Found {len(subnets)} subnet(s)")
        
        # Get route tables to determine public/private
        route_tables = {}
        try:
            rt_response = ec2_client.describe_route_tables()
            for rt in rt_response.get("RouteTables", []):
                for association in rt.get("Associations", []):
                    subnet_id = association.get("SubnetId")
                    if subnet_id:
                        route_tables[subnet_id] = rt
        except Exception:
            pass
        
        output_dir = _resolve_output_dir(args)
        
        # Group subnets by VPC ID
        subnets_by_vpc = {}
        for subnet in subnets:
            vpc_id = subnet.get("VpcId")
            if vpc_id not in subnets_by_vpc:
                subnets_by_vpc[vpc_id] = []
            subnets_by_vpc[vpc_id].append(subnet)
        
        # Process subnets by VPC
        for vpc_id, vpc_subnets in subnets_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            subnet_data = []
            for subnet in vpc_subnets:
                subnet_id = subnet.get("SubnetId")
                subnet_info = {
                    "SubnetId": subnet_id,
                    "VpcId": vpc_id,
                    "CidrBlock": subnet.get("CidrBlock"),
                    "AvailabilityZone": subnet.get("AvailabilityZone"),
                    "AvailabilityZoneId": subnet.get("AvailabilityZoneId"),
                    "Tags": subnet.get("Tags", []),
                    "State": subnet.get("State"),
                    "Ipv6CidrBlockAssociationSet": subnet.get("Ipv6CidrBlockAssociationSet", []),
                    "MapPublicIpOnLaunch": subnet.get("MapPublicIpOnLaunch", False),
                }
                
                # Determine if public/private based on route table
                rt = route_tables.get(subnet_id)
                if rt:
                    subnet_info["RouteTableId"] = rt.get("RouteTableId")
                    # Check if route to IGW exists
                    is_public = False
                    for route in rt.get("Routes", []):
                        gateway_id = route.get("GatewayId", "")
                        if gateway_id.startswith("igw-"):
                            is_public = True
                            break
                    subnet_info["IsPublic"] = is_public
                else:
                    subnet_info["IsPublic"] = None  # Unknown
                
                subnet_data.append(subnet_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_subnets_{vpc_id}.json"
            filepath = _save_json_file(output_dir, filename, subnet_data)
            if filepath:
                print(f"      ✓ Saved {len(subnet_data)} subnet(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing subnets: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

