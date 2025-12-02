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


def run_vpc_routes(args):
    """Collect VPC route table information (describe_route_tables)."""
    print("[+] VPC Routes Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing route tables...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_route_tables(Filters=filters if filters else None)
        route_tables = response.get("RouteTables", [])
        
        if not route_tables:
            print("    ⚠ No route tables found")
            return
        
        print(f"    ✓ Found {len(route_tables)} route table(s)")
        
        output_dir = _resolve_output_dir(args)
        
        # Group route tables by VPC ID
        routes_by_vpc = {}
        for rt in route_tables:
            vpc_id = rt.get("VpcId")
            if vpc_id not in routes_by_vpc:
                routes_by_vpc[vpc_id] = []
            routes_by_vpc[vpc_id].append(rt)
        
        # Process route tables by VPC
        for vpc_id, vpc_route_tables in routes_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            route_data = []
            for rt in vpc_route_tables:
                routes = []
                for route in rt.get("Routes", []):
                    route_info = {
                        "DestinationCidrBlock": route.get("DestinationCidrBlock"),
                        "DestinationIpv6CidrBlock": route.get("DestinationIpv6CidrBlock"),
                        "DestinationPrefixListId": route.get("DestinationPrefixListId"),
                        "GatewayId": route.get("GatewayId"),
                        "InstanceId": route.get("InstanceId"),
                        "InstanceOwnerId": route.get("InstanceOwnerId"),
                        "NetworkInterfaceId": route.get("NetworkInterfaceId"),
                        "Origin": route.get("Origin"),
                        "State": route.get("State"),
                        "TransitGatewayId": route.get("TransitGatewayId"),
                        "VpcPeeringConnectionId": route.get("VpcPeeringConnectionId"),
                        "NatGatewayId": route.get("NatGatewayId"),
                        "LocalGatewayId": route.get("LocalGatewayId"),
                    }
                    
                    # Determine target type
                    target_type = "local"
                    if route_info["GatewayId"]:
                        if route_info["GatewayId"].startswith("igw-"):
                            target_type = "internet_gateway"
                        elif route_info["GatewayId"].startswith("vgw-"):
                            target_type = "virtual_private_gateway"
                    elif route_info["NatGatewayId"]:
                        target_type = "nat_gateway"
                    elif route_info["VpcPeeringConnectionId"]:
                        target_type = "vpc_peering"
                    elif route_info["TransitGatewayId"]:
                        target_type = "transit_gateway"
                    elif route_info["InstanceId"]:
                        target_type = "instance"
                    elif route_info["NetworkInterfaceId"]:
                        target_type = "network_interface"
                    
                    route_info["TargetType"] = target_type
                    routes.append(route_info)
                
                rt_info = {
                    "RouteTableId": rt.get("RouteTableId"),
                    "VpcId": vpc_id,
                    "Tags": rt.get("Tags", []),
                    "Associations": rt.get("Associations", []),
                    "Routes": routes,
                }
                route_data.append(rt_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_route_tables_{vpc_id}.json"
            filepath = _save_json_file(output_dir, filename, route_data)
            if filepath:
                print(f"      ✓ Saved {len(route_data)} route table(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing route tables: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

