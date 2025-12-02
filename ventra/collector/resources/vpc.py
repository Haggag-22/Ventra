"""
VPC Comprehensive Collector
Collects all VPC resources for a given VPC ID: VPC info, subnets, route tables, 
security groups, network ACLs, endpoints, internet gateways, NAT gateways, and flow logs.
"""
import os
import json
import boto3
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
    if hasattr(args, "case_dir") and args.case_dir:
        output_base = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_base = args.output
    else:
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


def run_vpc(args):
    """Collect all VPC resources for a given VPC ID."""
    vpc_id = getattr(args, "vpc_id", None)
    
    if not vpc_id:
        print("❌ Error: --vpc-id parameter is required")
        print("   Usage: ventra collect resources vpc --case <case> --vpc-id <vpc-id>")
        return
    
    print(f"[+] VPC Comprehensive Collector")
    print(f"    VPC ID:      {vpc_id}")
    print(f"    Region:     {args.region}\n")
    
    output_dir = _resolve_output_dir(args)
    print(f"    Output:      {output_dir}\n")
    
    try:
        ec2_client = _get_ec2_client(args.region)
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting AWS clients: {e}")
        return
    
    # Initialize comprehensive data structure
    all_data = {
        "VpcId": vpc_id,
        "Region": args.region,
        "VPCs": [],
        "Subnets": [],
        "RouteTables": [],
        "SecurityGroups": [],
        "NetworkAcls": [],
        "VpcEndpoints": [],
        "InternetGateways": [],
        "NatGateways": [],
        "FlowLogs": [],
    }
    
    try:
        # 1. Collect VPC information
        print("[+] Collecting VPC information...")
        try:
            vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
            vpcs = vpc_response.get("Vpcs", [])
            if vpcs:
                all_data["VPCs"] = vpcs
                print(f"    ✓ Collected VPC information")
            else:
                print(f"    ⚠ VPC {vpc_id} not found")
                return
        except ClientError as e:
            print(f"    ⚠ Error describing VPC: {e}")
        
        # 2. Collect Subnets
        print("[+] Collecting subnets...")
        try:
            subnets_response = ec2_client.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            subnets = subnets_response.get("Subnets", [])
            all_data["Subnets"] = subnets
            print(f"    ✓ Collected {len(subnets)} subnet(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing subnets: {e}")
        
        # 3. Collect Route Tables
        print("[+] Collecting route tables...")
        try:
            routes_response = ec2_client.describe_route_tables(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            route_tables = routes_response.get("RouteTables", [])
            all_data["RouteTables"] = route_tables
            print(f"    ✓ Collected {len(route_tables)} route table(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing route tables: {e}")
        
        # 4. Collect Security Groups
        print("[+] Collecting security groups...")
        try:
            sgs_response = ec2_client.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            security_groups = sgs_response.get("SecurityGroups", [])
            all_data["SecurityGroups"] = security_groups
            print(f"    ✓ Collected {len(security_groups)} security group(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing security groups: {e}")
        
        # 5. Collect Network ACLs
        print("[+] Collecting network ACLs...")
        try:
            nacls_response = ec2_client.describe_network_acls(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            nacls = nacls_response.get("NetworkAcls", [])
            all_data["NetworkAcls"] = nacls
            print(f"    ✓ Collected {len(nacls)} network ACL(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing network ACLs: {e}")
        
        # 6. Collect VPC Endpoints
        print("[+] Collecting VPC endpoints...")
        try:
            endpoints_response = ec2_client.describe_vpc_endpoints(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            endpoints = endpoints_response.get("VpcEndpoints", [])
            all_data["VpcEndpoints"] = endpoints
            print(f"    ✓ Collected {len(endpoints)} VPC endpoint(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing VPC endpoints: {e}")
        
        # 7. Collect Internet Gateways
        print("[+] Collecting internet gateways...")
        try:
            igws_response = ec2_client.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            )
            igws = igws_response.get("InternetGateways", [])
            all_data["InternetGateways"] = igws
            print(f"    ✓ Collected {len(igws)} internet gateway(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing internet gateways: {e}")
        
        # 8. Collect NAT Gateways
        print("[+] Collecting NAT gateways...")
        try:
            nats_response = ec2_client.describe_nat_gateways(
                Filter=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            nat_gateways = nats_response.get("NatGateways", [])
            all_data["NatGateways"] = nat_gateways
            print(f"    ✓ Collected {len(nat_gateways)} NAT gateway(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing NAT gateways: {e}")
        
        # 9. Collect Flow Logs
        print("[+] Collecting flow logs...")
        try:
            flow_logs_response = ec2_client.describe_flow_logs(
                Filter=[
                    {"Name": "resource-id", "Values": [vpc_id]},
                    {"Name": "resource-type", "Values": ["VPC"]}
                ]
            )
            flow_logs = flow_logs_response.get("FlowLogs", [])
            all_data["FlowLogs"] = flow_logs
            print(f"    ✓ Collected {len(flow_logs)} flow log configuration(s)")
        except ClientError as e:
            print(f"    ⚠ Error describing flow logs: {e}")
        
        # Save comprehensive data
        filename = f"vpc_{vpc_id}.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all VPC data → {filepath}")
            print(f"    VPCs: {len(all_data['VPCs'])}")
            print(f"    Subnets: {len(all_data['Subnets'])}")
            print(f"    Route Tables: {len(all_data['RouteTables'])}")
            print(f"    Security Groups: {len(all_data['SecurityGroups'])}")
            print(f"    Network ACLs: {len(all_data['NetworkAcls'])}")
            print(f"    VPC Endpoints: {len(all_data['VpcEndpoints'])}")
            print(f"    Internet Gateways: {len(all_data['InternetGateways'])}")
            print(f"    NAT Gateways: {len(all_data['NatGateways'])}")
            print(f"    Flow Logs: {len(all_data['FlowLogs'])}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

