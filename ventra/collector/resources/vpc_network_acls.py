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


def run_vpc_nacls(args):
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
            filename = f"vpc_network_acls_{vpc_id}.json"
            filepath = _save_json_file(output_dir, filename, nacl_data)
            if filepath:
                print(f"      ✓ Saved {len(nacl_data)} network ACL(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing network ACLs: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

