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


def run_vpc_security_groups(args):
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
            filename = f"vpc_security_groups_{vpc_id}.json"
            filepath = _save_json_file(output_dir, filename, sg_data)
            if filepath:
                print(f"      ✓ Saved {len(sg_data)} security group(s) → {filepath}")
        
        print()
        
    except ClientError as e:
        print(f"❌ Error describing security groups: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

