"""
EC2 Instances Collector
Collects EC2 instance metadata and configuration.
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


def run_ec2_instances(args):
    """Collect EC2 instance metadata."""
    instance_ids = getattr(args, "instance", None)
    if isinstance(instance_ids, str):
        instance_ids = [i.strip() for i in instance_ids.split(",") if i.strip()]
    
    print(f"[+] EC2 Instances Collector")
    print(f"    Region:      {args.region}")
    if instance_ids:
        print(f"    Instances:   {', '.join(instance_ids)}")
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
        # Describe instances
        filters = []
        if instance_ids:
            filters.append({"Name": "instance-id", "Values": instance_ids})
        
        response = ec2_client.describe_instances(Filters=filters if filters else None)
        
        instances = []
        for reservation in response.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))
        
        if not instances:
            print("    ⚠ No instances found")
            return
        
        print(f"    ✓ Found {len(instances)} instance(s)")
        
        # Process each instance
        instance_data = []
        for instance in instances:
            instance_info = {
                "InstanceId": instance.get("InstanceId"),
                "InstanceType": instance.get("InstanceType"),
                "State": instance.get("State", {}).get("Name"),
                "LaunchTime": str(instance.get("LaunchTime", "")),
                "ImageId": instance.get("ImageId"),
                "KeyName": instance.get("KeyName"),
                "VpcId": instance.get("VpcId"),
                "SubnetId": instance.get("SubnetId"),
                "PrivateIpAddress": instance.get("PrivateIpAddress"),
                "PublicIpAddress": instance.get("PublicIpAddress"),
                "PrivateDnsName": instance.get("PrivateDnsName"),
                "PublicDnsName": instance.get("PublicDnsName"),
                "SecurityGroups": instance.get("SecurityGroups", []),
                "IamInstanceProfile": instance.get("IamInstanceProfile"),
                "Tags": instance.get("Tags", []),
                "NetworkInterfaces": instance.get("NetworkInterfaces", []),
                "BlockDeviceMappings": instance.get("BlockDeviceMappings", []),
            }
            instance_data.append(instance_info)
        
        # Save instances
        filename = "ec2_instances.json" if not instance_ids else f"ec2_instances_{'_'.join(instance_ids[:3])}.json"
        filepath = _save_json_file(output_dir, filename, instance_data)
        if filepath:
            print(f"\n[✓] Saved {len(instance_data)} instance(s) → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")







