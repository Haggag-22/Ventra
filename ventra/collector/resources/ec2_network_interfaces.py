"""
EC2 Network Interfaces Collector
Collects EC2 network interface configurations.
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


def run_ec2_network_interfaces(args):
    """Collect EC2 network interface configurations."""
    interface_ids = getattr(args, "interface", None)
    if isinstance(interface_ids, str):
        interface_ids = [i.strip() for i in interface_ids.split(",") if i.strip()]
    
    print(f"[+] EC2 Network Interfaces Collector")
    print(f"    Region:      {args.region}")
    if interface_ids:
        print(f"    Interfaces:  {', '.join(interface_ids)}")
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
        # Describe network interfaces
        filters = []
        if interface_ids:
            filters.append({"Name": "network-interface-id", "Values": interface_ids})
        
        response = ec2_client.describe_network_interfaces(Filters=filters if filters else None)
        network_interfaces = response.get("NetworkInterfaces", [])
        
        if not network_interfaces:
            print("    ⚠ No network interfaces found")
            return
        
        print(f"    ✓ Found {len(network_interfaces)} network interface(s)")
        
        # Process network interfaces
        eni_data = []
        for eni in network_interfaces:
            eni_info = {
                "NetworkInterfaceId": eni.get("NetworkInterfaceId"),
                "SubnetId": eni.get("SubnetId"),
                "VpcId": eni.get("VpcId"),
                "AvailabilityZone": eni.get("AvailabilityZone"),
                "Description": eni.get("Description"),
                "PrivateIpAddress": eni.get("PrivateIpAddress"),
                "PrivateIpAddresses": eni.get("PrivateIpAddresses", []),
                "PublicIp": eni.get("Association", {}).get("PublicIp") if eni.get("Association") else None,
                "Groups": eni.get("Groups", []),
                "Attachment": eni.get("Attachment", {}),
                "InterfaceType": eni.get("InterfaceType"),
                "Ipv6Addresses": eni.get("Ipv6Addresses", []),
                "MacAddress": eni.get("MacAddress"),
                "OwnerId": eni.get("OwnerId"),
                "RequesterId": eni.get("RequesterId"),
                "RequesterManaged": eni.get("RequesterManaged", False),
                "SourceDestCheck": eni.get("SourceDestCheck"),
                "Status": eni.get("Status"),
                "Tags": eni.get("Tags", []),
            }
            eni_data.append(eni_info)
        
        # Save network interfaces
        filename = "ec2_network_interfaces.json" if not interface_ids else f"ec2_network_interfaces_{'_'.join(interface_ids[:3])}.json"
        filepath = _save_json_file(output_dir, filename, eni_data)
        if filepath:
            print(f"\n[✓] Saved {len(eni_data)} network interface(s) → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")







