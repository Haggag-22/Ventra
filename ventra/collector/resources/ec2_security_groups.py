"""
EC2 Security Groups Collector
Collects EC2 security group configurations.
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


def run_ec2_security_groups(args):
    """Collect EC2 security group configurations."""
    group_ids = getattr(args, "group", None)
    if isinstance(group_ids, str):
        group_ids = [g.strip() for g in group_ids.split(",") if g.strip()]
    
    print(f"[+] EC2 Security Groups Collector")
    print(f"    Region:      {args.region}")
    if group_ids:
        print(f"    Groups:      {', '.join(group_ids)}")
    print()
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "resources")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    try:
        # Describe security groups
        filters = []
        if group_ids:
            filters.append({"Name": "group-id", "Values": group_ids})
        
        response = ec2_client.describe_security_groups(Filters=filters if filters else None)
        security_groups = response.get("SecurityGroups", [])
        
        if not security_groups:
            print("    ⚠ No security groups found")
            return
        
        print(f"    ✓ Found {len(security_groups)} security group(s)")
        
        # Process security groups
        sg_data = []
        for sg in security_groups:
            sg_info = {
                "GroupId": sg.get("GroupId"),
                "GroupName": sg.get("GroupName"),
                "Description": sg.get("Description"),
                "VpcId": sg.get("VpcId"),
                "OwnerId": sg.get("OwnerId"),
                "Tags": sg.get("Tags", []),
                "IpPermissions": sg.get("IpPermissions", []),  # Inbound rules
                "IpPermissionsEgress": sg.get("IpPermissionsEgress", []),  # Outbound rules
            }
            sg_data.append(sg_info)
        
        # Save security groups
        filename = "ec2_security_groups.json" if not group_ids else f"ec2_security_groups_{'_'.join(group_ids[:3])}.json"
        filepath = _save_json_file(output_dir, filename, sg_data)
        if filepath:
            print(f"\n[✓] Saved {len(sg_data)} security group(s) → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")







