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


def collect_vpc_info(args):
    """Collect VPC information (describe_vpcs)."""
    print("[+] VPC Info Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing VPCs...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_vpcs(Filters=filters if filters else None)
        vpcs = response.get("Vpcs", [])
        
        if not vpcs:
            print("    ⚠ No VPCs found")
            return
        
        print(f"    ✓ Found {len(vpcs)} VPC(s)")
        
        output_dir = _resolve_output_dir(args)
        
        # Process VPCs - save each VPC with VPC ID in filename
        for vpc in vpcs:
            vpc_id = vpc.get("VpcId")
            print(f"    Processing {vpc_id}")
            
            vpc_info = {
                "VpcId": vpc_id,
                "CidrBlock": vpc.get("CidrBlock"),
                "CidrBlockAssociationSet": vpc.get("CidrBlockAssociationSet", []),
                "DhcpOptionsId": vpc.get("DhcpOptionsId"),
                "State": vpc.get("State"),
                "Tags": vpc.get("Tags", []),
                "InstanceTenancy": vpc.get("InstanceTenancy"),
                "Ipv6CidrBlockAssociationSet": vpc.get("Ipv6CidrBlockAssociationSet", []),
                "IsDefault": vpc.get("IsDefault", False),
            }
            
            # Get DNS options if available
            try:
                dhcp_options = ec2_client.describe_dhcp_options(DhcpOptionsIds=[vpc.get("DhcpOptionsId")])
                if dhcp_options.get("DhcpOptions"):
                    vpc_info["DhcpOptions"] = dhcp_options["DhcpOptions"][0]
            except Exception:
                pass
            
            # Save to file with VPC ID in filename
            filename = f"vpc_{vpc_id}_info.json"
            filepath = _save_json_file(output_dir, filename, vpc_info)
            if filepath:
                print(f"      ✓ Saved → {filepath}")
        
        print()
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        print(f"❌ Error describing VPCs: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_subnets(args):
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
            filename = f"vpc_{vpc_id}_subnets.json"
            filepath = _save_json_file(output_dir, filename, subnet_data)
            if filepath:
                print(f"      ✓ Saved {len(subnet_data)} subnet(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing subnets: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_routes(args):
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
            filename = f"vpc_{vpc_id}_route_tables.json"
            filepath = _save_json_file(output_dir, filename, route_data)
            if filepath:
                print(f"      ✓ Saved {len(route_data)} route table(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing route tables: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_security_groups(args):
    """Collect VPC security group information (describe_security_groups)."""
    print("[+] VPC Security Groups Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing security groups...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_security_groups(Filters=filters if filters else None)
        security_groups = response.get("SecurityGroups", [])
        
        if not security_groups:
            print("    ⚠ No security groups found")
            return
        
        print(f"    ✓ Found {len(security_groups)} security group(s)")
        
        output_dir = _resolve_output_dir(args)
        
        # Group security groups by VPC ID
        sgs_by_vpc = {}
        for sg in security_groups:
            vpc_id = sg.get("VpcId")
            if vpc_id not in sgs_by_vpc:
                sgs_by_vpc[vpc_id] = []
            sgs_by_vpc[vpc_id].append(sg)
        
        # Process security groups by VPC
        for vpc_id, vpc_sgs in sgs_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            sg_data = []
            for sg in vpc_sgs:
                sg_info = {
                    "GroupId": sg.get("GroupId"),
                    "GroupName": sg.get("GroupName"),
                    "Description": sg.get("Description"),
                    "VpcId": vpc_id,
                    "OwnerId": sg.get("OwnerId"),
                    "Tags": sg.get("Tags", []),
                    "IpPermissions": sg.get("IpPermissions", []),  # Inbound rules
                    "IpPermissionsEgress": sg.get("IpPermissionsEgress", []),  # Outbound rules
                }
                sg_data.append(sg_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_{vpc_id}_security_groups.json"
            filepath = _save_json_file(output_dir, filename, sg_data)
            if filepath:
                print(f"      ✓ Saved {len(sg_data)} security group(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing security groups: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_nacls(args):
    """Collect VPC network ACL information (describe_network_acls)."""
    print("[+] VPC Network ACLs Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing network ACLs...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_network_acls(Filters=filters if filters else None)
        nacls = response.get("NetworkAcls", [])
        
        if not nacls:
            print("    ⚠ No network ACLs found")
            return
        
        print(f"    ✓ Found {len(nacls)} network ACL(s)")
        
        output_dir = _resolve_output_dir(args)
        
        # Group NACLs by VPC ID
        nacls_by_vpc = {}
        for nacl in nacls:
            vpc_id = nacl.get("VpcId")
            if vpc_id not in nacls_by_vpc:
                nacls_by_vpc[vpc_id] = []
            nacls_by_vpc[vpc_id].append(nacl)
        
        # Process NACLs by VPC
        for vpc_id, vpc_nacls in nacls_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            nacl_data = []
            for nacl in vpc_nacls:
                entries = []
                for entry in nacl.get("Entries", []):
                    entry_info = {
                        "RuleNumber": entry.get("RuleNumber"),
                        "Protocol": entry.get("Protocol"),
                        "RuleAction": entry.get("RuleAction"),  # allow or deny
                        "Egress": entry.get("Egress"),  # true for outbound, false for inbound
                        "CidrBlock": entry.get("CidrBlock"),
                        "Ipv6CidrBlock": entry.get("Ipv6CidrBlock"),
                        "IcmpTypeCode": entry.get("IcmpTypeCode"),
                        "PortRange": entry.get("PortRange"),
                    }
                    entries.append(entry_info)
                
                nacl_info = {
                    "NetworkAclId": nacl.get("NetworkAclId"),
                    "VpcId": vpc_id,
                    "IsDefault": nacl.get("IsDefault", False),
                    "Tags": nacl.get("Tags", []),
                    "Associations": nacl.get("Associations", []),
                    "Entries": entries,
                }
                nacl_data.append(nacl_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_{vpc_id}_nacls.json"
            filepath = _save_json_file(output_dir, filename, nacl_data)
            if filepath:
                print(f"      ✓ Saved {len(nacl_data)} network ACL(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing network ACLs: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_endpoints(args):
    """Collect VPC endpoint information (describe_vpc_endpoints)."""
    print("[+] VPC Endpoints Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing VPC endpoints...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_vpc_endpoints(Filters=filters if filters else None)
        endpoints = response.get("VpcEndpoints", [])
        
        if not endpoints:
            print("    ⚠ No VPC endpoints found")
            return
        
        print(f"    ✓ Found {len(endpoints)} VPC endpoint(s)")
        
        output_dir = _resolve_output_dir(args)
        
        # Group endpoints by VPC ID
        endpoints_by_vpc = {}
        for endpoint in endpoints:
            vpc_id = endpoint.get("VpcId")
            if vpc_id not in endpoints_by_vpc:
                endpoints_by_vpc[vpc_id] = []
            endpoints_by_vpc[vpc_id].append(endpoint)
        
        # Process endpoints by VPC
        for vpc_id, vpc_endpoints in endpoints_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            endpoint_data = []
            for endpoint in vpc_endpoints:
                endpoint_info = {
                    "VpcEndpointId": endpoint.get("VpcEndpointId"),
                    "VpcEndpointType": endpoint.get("VpcEndpointType"),
                    "VpcId": vpc_id,
                    "ServiceName": endpoint.get("ServiceName"),
                    "State": endpoint.get("State"),
                    "PolicyDocument": endpoint.get("PolicyDocument"),
                    "RouteTableIds": endpoint.get("RouteTableIds", []),
                    "SubnetIds": endpoint.get("SubnetIds", []),
                    "Groups": endpoint.get("Groups", []),
                    "PrivateDnsEnabled": endpoint.get("PrivateDnsEnabled"),
                    "RequesterManaged": endpoint.get("RequesterManaged", False),
                    "NetworkInterfaceIds": endpoint.get("NetworkInterfaceIds", []),
                    "DnsEntries": endpoint.get("DnsEntries", []),
                    "CreationTimestamp": str(endpoint.get("CreationTimestamp", "")),
                    "Tags": endpoint.get("Tags", []),
                }
                endpoint_data.append(endpoint_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_{vpc_id}_endpoints.json"
            filepath = _save_json_file(output_dir, filename, endpoint_data)
            if filepath:
                print(f"      ✓ Saved {len(endpoint_data)} endpoint(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing VPC endpoints: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_internet_gateways(args):
    """Collect internet gateway information (describe_internet_gateways)."""
    print("[+] VPC Internet Gateways Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing internet gateways...")
        
        response = ec2_client.describe_internet_gateways()
        igws = response.get("InternetGateways", [])
        
        # Filter by VPC if specified
        if hasattr(args, "vpc_id") and args.vpc_id:
            print(f"    Filtering by VPC ID: {args.vpc_id}")
            igws = [igw for igw in igws if any(
                att.get("VpcId") == args.vpc_id 
                for att in igw.get("Attachments", [])
            )]
        
        if not igws:
            print("    ⚠ No internet gateways found")
            return
        
        print(f"    ✓ Found {len(igws)} internet gateway(s)")
        
        output_dir = _resolve_output_dir(args)
        
        # Group IGWs by VPC ID
        igws_by_vpc = {}
        for igw in igws:
            attachments = igw.get("Attachments", [])
            for att in attachments:
                vpc_id = att.get("VpcId")
                if vpc_id:
                    if vpc_id not in igws_by_vpc:
                        igws_by_vpc[vpc_id] = []
                    igws_by_vpc[vpc_id].append(igw)
        
        # Process IGWs by VPC
        for vpc_id, vpc_igws in igws_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            igw_data = []
            for igw in vpc_igws:
                igw_info = {
                    "InternetGatewayId": igw.get("InternetGatewayId"),
                    "OwnerId": igw.get("OwnerId"),
                    "Tags": igw.get("Tags", []),
                    "Attachments": igw.get("Attachments", []),
                }
                igw_data.append(igw_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_{vpc_id}_internet_gateways.json"
            filepath = _save_json_file(output_dir, filename, igw_data)
            if filepath:
                print(f"      ✓ Saved {len(igw_data)} internet gateway(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing internet gateways: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_nat_gateways(args):
    """Collect NAT gateway information (describe_nat_gateways)."""
    print("[+] VPC NAT Gateways Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing NAT gateways...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_nat_gateways(Filters=filters if filters else None)
        nat_gateways = response.get("NatGateways", [])
        
        if not nat_gateways:
            print("    ⚠ No NAT gateways found")
            return
        
        print(f"    ✓ Found {len(nat_gateways)} NAT gateway(s)")
        
        output_dir = _resolve_output_dir(args)
        
        # Group NAT gateways by VPC ID
        nats_by_vpc = {}
        for nat in nat_gateways:
            vpc_id = nat.get("VpcId")
            if vpc_id not in nats_by_vpc:
                nats_by_vpc[vpc_id] = []
            nats_by_vpc[vpc_id].append(nat)
        
        # Process NAT gateways by VPC
        for vpc_id, vpc_nats in nats_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            nat_data = []
            for nat in vpc_nats:
                nat_info = {
                    "NatGatewayId": nat.get("NatGatewayId"),
                    "SubnetId": nat.get("SubnetId"),
                    "VpcId": vpc_id,
                    "State": nat.get("State"),
                    "CreateTime": str(nat.get("CreateTime", "")),
                    "DeleteTime": str(nat.get("DeleteTime", "")) if nat.get("DeleteTime") else None,
                    "NatGatewayAddresses": nat.get("NatGatewayAddresses", []),
                    "Tags": nat.get("Tags", []),
                }
                
                # Extract public IPs
                public_ips = []
                for addr in nat_info["NatGatewayAddresses"]:
                    if addr.get("PublicIp"):
                        public_ips.append(addr.get("PublicIp"))
                nat_info["PublicIps"] = public_ips
                
                nat_data.append(nat_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_{vpc_id}_nat_gateways.json"
            filepath = _save_json_file(output_dir, filename, nat_data)
            if filepath:
                print(f"      ✓ Saved {len(nat_data)} NAT gateway(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing NAT gateways: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_flow_logs(args):
    """Collect VPC flow log configuration and optionally recent log events."""
    print("[+] VPC Flow Logs Collector")
    print(f"    Region:     {args.region}")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        print("[+] Describing flow logs...")
        filters = []
        if hasattr(args, "vpc_id") and args.vpc_id:
            filters.append({"Name": "resource-id", "Values": [args.vpc_id]})
            print(f"    Filtering by VPC ID: {args.vpc_id}")
        
        response = ec2_client.describe_flow_logs(Filters=filters if filters else None)
        flow_logs = response.get("FlowLogs", [])
        
        if not flow_logs:
            print("    ⚠ No flow logs configured in this region")
            return
        
        print(f"    ✓ Found {len(flow_logs)} flow log configuration(s)")
        
        # Build a map of resource IDs to VPC IDs for subnets and ENIs
        resource_to_vpc = {}
        try:
            # Get all subnets
            subnets_response = ec2_client.describe_subnets()
            for subnet in subnets_response.get("Subnets", []):
                resource_to_vpc[subnet.get("SubnetId")] = subnet.get("VpcId")
            
            # Get all network interfaces
            enis_response = ec2_client.describe_network_interfaces()
            for eni in enis_response.get("NetworkInterfaces", []):
                resource_to_vpc[eni.get("NetworkInterfaceId")] = eni.get("VpcId")
        except Exception:
            pass
        
        # Group flow logs by VPC ID
        flow_logs_by_vpc = {}
        hours = getattr(args, "hours", None)
        
        for flow_log in flow_logs:
            resource_id = flow_log.get("ResourceId")
            resource_type = flow_log.get("ResourceType")
            
            # Determine VPC ID
            vpc_id = None
            if resource_type == "VPC":
                vpc_id = resource_id
            elif resource_id in resource_to_vpc:
                vpc_id = resource_to_vpc[resource_id]
            
            # If we can't determine VPC ID, use resource_id as folder name
            if not vpc_id:
                vpc_id = resource_id
            
            if vpc_id not in flow_logs_by_vpc:
                flow_logs_by_vpc[vpc_id] = []
            flow_logs_by_vpc[vpc_id].append(flow_log)
        
        output_dir = _resolve_output_dir(args)
        
        # Process flow logs by VPC
        for vpc_id, vpc_flow_logs in flow_logs_by_vpc.items():
            print(f"    Processing {vpc_id}")
            
            flow_log_data = []
            for flow_log in vpc_flow_logs:
                flow_log_info = {
                    "FlowLogId": flow_log.get("FlowLogId"),
                    "FlowLogStatus": flow_log.get("FlowLogStatus"),
                    "ResourceId": flow_log.get("ResourceId"),
                    "ResourceType": flow_log.get("ResourceType"),
                    "TrafficType": flow_log.get("TrafficType"),
                    "LogDestinationType": flow_log.get("LogDestinationType"),
                    "LogDestination": flow_log.get("LogDestination"),
                    "LogFormat": flow_log.get("LogFormat"),
                    "DeliverLogsStatus": flow_log.get("DeliverLogsStatus"),
                    "DeliverLogsErrorMessage": flow_log.get("DeliverLogsErrorMessage"),
                    "CreationTime": str(flow_log.get("CreationTime", "")),
                    "Tags": flow_log.get("Tags", []),
                }
                
                # Parse destination details
                destination_type = flow_log_info["LogDestinationType"]
                destination = flow_log_info["LogDestination"]
                
                if destination_type == "cloud-watch-logs" and destination:
                    # Parse CloudWatch Logs ARN: arn:aws:logs:region:account:log-group:name
                    # Format: arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/flowlogs
                    try:
                        arn_parts = destination.split(":")
                        if len(arn_parts) >= 7:
                            flow_log_info["LogGroupRegion"] = arn_parts[3]
                            log_group_arn = ":".join(arn_parts[6:])
                            flow_log_info["LogGroupName"] = log_group_arn.replace("log-group:", "")
                    except Exception:
                        pass
                    
                    # Optionally retrieve recent log events
                    if hours:
                        print(f"      [+] Retrieving last {hours} hours of flow log events from CloudWatch Logs...")
                        try:
                            logs_client = _get_cloudwatch_logs_client(flow_log_info.get("LogGroupRegion", args.region))
                            log_group_name = flow_log_info.get("LogGroupName")
                            
                            if log_group_name:
                                end_time = datetime.now(timezone.utc)
                                start_time = end_time - timedelta(hours=hours)
                                
                                events = []
                                paginator = logs_client.get_paginator("filter_log_events")
                                pages = paginator.paginate(
                                    logGroupName=log_group_name,
                                    startTime=int(start_time.timestamp() * 1000),
                                    endTime=int(end_time.timestamp() * 1000),
                                )
                                
                                for page in pages:
                                    for event in page.get("events", []):
                                        events.append({
                                            "timestamp": event.get("timestamp"),
                                            "message": event.get("message"),
                                            "ingestionTime": event.get("ingestionTime"),
                                        })
                                
                                if events:
                                    # Save events to JSONL file directly in output directory
                                    flow_log_id_safe = flow_log_info["FlowLogId"].replace("/", "_")
                                    events_file = os.path.join(output_dir, f"vpc_{vpc_id}_flowlog_{flow_log_id_safe}_recent.jsonl")
                                    
                                    with open(events_file, "w", encoding="utf-8") as f:
                                        for event in events:
                                            f.write(json.dumps(event, default=str) + "\n")
                                    
                                    flow_log_info["RecentEventsFile"] = events_file
                                    flow_log_info["RecentEventsCount"] = len(events)
                                    print(f"        ✓ Retrieved {len(events)} log event(s)")
                                else:
                                    print(f"        ⚠ No events found in last {hours} hours")
                        except Exception as e:
                            print(f"        ⚠ Error retrieving log events: {e}")
                            flow_log_info["RecentEventsError"] = str(e)
                
                elif destination_type == "s3" and destination:
                    # Parse S3 ARN: arn:aws:s3:::bucket-name/prefix
                    try:
                        if destination.startswith("arn:aws:s3:::"):
                            s3_path = destination.replace("arn:aws:s3:::", "")
                            parts = s3_path.split("/", 1)
                            flow_log_info["S3Bucket"] = parts[0]
                            flow_log_info["S3Prefix"] = parts[1] if len(parts) > 1 else ""
                        elif destination.startswith("arn:aws:s3"):
                            # Full ARN format
                            arn_parts = destination.split(":")
                            if len(arn_parts) >= 6:
                                s3_path = ":".join(arn_parts[5:])
                                parts = s3_path.split("/", 1)
                                flow_log_info["S3Bucket"] = parts[0]
                                flow_log_info["S3Prefix"] = parts[1] if len(parts) > 1 else ""
                    except Exception:
                        pass
                
                flow_log_data.append(flow_log_info)
            
            # Save to file with VPC ID in filename
            filename = f"vpc_{vpc_id}_flow_logs_config.json"
            filepath = _save_json_file(output_dir, filename, flow_log_data)
            if filepath:
                print(f"      ✓ Saved {len(flow_log_data)} flow log configuration(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing flow logs: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def collect_vpc_all(args):
    """Collect all VPC information into a single combined file."""
    print("[+] VPC All Collector")
    print(f"    Region:     {args.region}")
    vpc_id = getattr(args, "vpc_id", None)
    if vpc_id:
        print(f"    VPC ID:     {vpc_id}")
    print()
    
    try:
        ec2_client = _get_ec2_client(args.region)
        logs_client = _get_cloudwatch_logs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting clients: {e}")
        return
    
    output_dir = _resolve_output_dir(args)
    print(f"    Output:     {output_dir}\n")
    
    try:
        all_data = {
            "VPCs": [],
            "Subnets": [],
            "RouteTables": [],
            "SecurityGroups": [],
            "NetworkACLs": [],
            "Endpoints": [],
            "InternetGateways": [],
            "NATGateways": [],
            "FlowLogs": [],
        }
        
        # Collect all VPC components with error handling - continue on errors
        filters = []
        if vpc_id:
            filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        
        # 1. VPCs
        print("[+] Collecting VPCs...")
        try:
            response = ec2_client.describe_vpcs(Filters=filters if filters else None)
            for vpc in response.get("Vpcs", []):
                vpc_info = {
                    "VpcId": vpc.get("VpcId"),
                    "CidrBlock": vpc.get("CidrBlock"),
                    "CidrBlockAssociationSet": vpc.get("CidrBlockAssociationSet", []),
                    "DhcpOptionsId": vpc.get("DhcpOptionsId"),
                    "State": vpc.get("State"),
                    "Tags": vpc.get("Tags", []),
                    "InstanceTenancy": vpc.get("InstanceTenancy"),
                    "Ipv6CidrBlockAssociationSet": vpc.get("Ipv6CidrBlockAssociationSet", []),
                    "IsDefault": vpc.get("IsDefault", False),
                }
                try:
                    dhcp_options = ec2_client.describe_dhcp_options(DhcpOptionsIds=[vpc.get("DhcpOptionsId")])
                    if dhcp_options.get("DhcpOptions"):
                        vpc_info["DhcpOptions"] = dhcp_options["DhcpOptions"][0]
                except Exception:
                    pass
                all_data["VPCs"].append(vpc_info)
            print(f"    ✓ Found {len(all_data['VPCs'])} VPC(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting VPCs: {e} (continuing)")
        
        # 2. Subnets
        print("[+] Collecting subnets...")
        try:
            response = ec2_client.describe_subnets(Filters=filters if filters else None)
            all_data["Subnets"] = response.get("Subnets", [])
            print(f"    ✓ Found {len(all_data['Subnets'])} subnet(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting subnets: {e} (continuing)")
        
        # 3. Route tables
        print("[+] Collecting route tables...")
        try:
            response = ec2_client.describe_route_tables(Filters=filters if filters else None)
            all_data["RouteTables"] = response.get("RouteTables", [])
            print(f"    ✓ Found {len(all_data['RouteTables'])} route table(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting route tables: {e} (continuing)")
        
        # 4. Security groups
        print("[+] Collecting security groups...")
        try:
            response = ec2_client.describe_security_groups(Filters=filters if filters else None)
            all_data["SecurityGroups"] = response.get("SecurityGroups", [])
            print(f"    ✓ Found {len(all_data['SecurityGroups'])} security group(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting security groups: {e} (continuing)")
        
        # 5. Network ACLs
        print("[+] Collecting network ACLs...")
        try:
            response = ec2_client.describe_network_acls(Filters=filters if filters else None)
            all_data["NetworkACLs"] = response.get("NetworkAcls", [])
            print(f"    ✓ Found {len(all_data['NetworkACLs'])} network ACL(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting network ACLs: {e} (continuing)")
        
        # 6. VPC endpoints
        print("[+] Collecting VPC endpoints...")
        try:
            response = ec2_client.describe_vpc_endpoints(Filters=filters if filters else None)
            all_data["Endpoints"] = response.get("VpcEndpoints", [])
            print(f"    ✓ Found {len(all_data['Endpoints'])} endpoint(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting endpoints: {e} (continuing)")
        
        # 7. Internet gateways
        print("[+] Collecting internet gateways...")
        try:
            response = ec2_client.describe_internet_gateways(Filters=filters if filters else None)
            all_data["InternetGateways"] = response.get("InternetGateways", [])
            print(f"    ✓ Found {len(all_data['InternetGateways'])} internet gateway/gateways")
        except Exception as e:
            print(f"    ⚠ Error collecting internet gateways: {e} (continuing)")
        
        # 8. NAT gateways
        print("[+] Collecting NAT gateways...")
        try:
            response = ec2_client.describe_nat_gateways(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else [])
            all_data["NATGateways"] = response.get("NatGateways", [])
            print(f"    ✓ Found {len(all_data['NATGateways'])} NAT gateway(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting NAT gateways: {e} (continuing)")
        
        # 9. Flow logs
        print("[+] Collecting flow logs...")
        try:
            flow_filters = filters if filters else None
            response = ec2_client.describe_flow_logs(Filters=flow_filters)
            all_data["FlowLogs"] = response.get("FlowLogs", [])
            print(f"    ✓ Found {len(all_data['FlowLogs'])} flow log(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting flow logs: {e} (continuing)")
        
        # Summary
        all_data["summary"] = {
            "total_vpcs": len(all_data["VPCs"]),
            "total_subnets": len(all_data["Subnets"]),
            "total_route_tables": len(all_data["RouteTables"]),
            "total_security_groups": len(all_data["SecurityGroups"]),
            "total_network_acls": len(all_data["NetworkACLs"]),
            "total_endpoints": len(all_data["Endpoints"]),
            "total_internet_gateways": len(all_data["InternetGateways"]),
            "total_nat_gateways": len(all_data["NATGateways"]),
            "total_flow_logs": len(all_data["FlowLogs"]),
        }
        
        # Save combined file
        filename = "vpc_all.json" if not vpc_id else f"vpc_{vpc_id}_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all VPC data → {filepath}\n")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

