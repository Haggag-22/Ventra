"""
EC2 All Collector
Collects all EC2 instance information (metadata, volumes, snapshots) into a single combined file.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile
from ventra.collector.ec2.ec2_metadata_passive import _extract_instance_summary


def _get_ec2_client(region):
    """EC2 client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("ec2")


def _get_iam_client(region):
    """IAM client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("iam")


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


def run_ec2_all(args):
    """Collect all EC2 instance data into a single file."""
    instance_id = getattr(args, "instance", None)
    
    if not instance_id:
        print("❌ Error: --instance parameter is required")
        print("   Usage: ventra collect ec2 all --case <case> --instance <instance_id>")
        return
    
    print(f"[+] EC2 All Collector")
    print(f"    Instance:    {instance_id}")
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
        ec2_client = _get_ec2_client(args.region)
        iam_client = _get_iam_client(args.region)
    except Exception as e:
        print(f"❌ Error getting clients: {e}")
        return
    
    # Collect all data
    all_data = {
        "InstanceId": instance_id,
        "InstanceInfo": None,
        "Volumes": [],
        "Snapshots": [],
        "ConsoleOutput": None,
        "IamProfile": None,
        "NetworkInterfaces": None,
        "Summary": None,
    }
    
    # 1. Describe instance
    print(f"[+] Collecting instance information...")
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if response.get("Reservations"):
            instance_data = response["Reservations"][0]["Instances"][0]
            all_data["InstanceInfo"] = instance_data
            print(f"    ✓ Collected instance info")
        else:
            print(f"    ❌ Instance {instance_id} not found")
            return
    except ClientError as e:
        print(f"    ⚠ Error describing instance: {e} (continuing)")
    except Exception as e:
        print(f"    ⚠ Error describing instance: {e} (continuing)")
    
    # 2. Collect volumes
    print(f"[+] Collecting volumes...")
    try:
        volumes_response = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
        )
        all_data["Volumes"] = volumes_response.get("Volumes", [])
        print(f"    ✓ Found {len(all_data['Volumes'])} volume(s)")
    except Exception as e:
        print(f"    ⚠ Error collecting volumes: {e} (continuing)")
    
    # 3. Collect snapshots for volumes
    print(f"[+] Collecting snapshots...")
    try:
        volume_ids = [v.get("VolumeId") for v in all_data["Volumes"]]
        if volume_ids:
            snapshots_response = ec2_client.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": volume_ids}]
            )
            all_data["Snapshots"] = snapshots_response.get("Snapshots", [])
            print(f"    ✓ Found {len(all_data['Snapshots'])} snapshot(s)")
        else:
            print(f"    ⚠ No volumes found, skipping snapshots")
    except Exception as e:
        print(f"    ⚠ Error collecting snapshots: {e} (continuing)")
    
    # 4. Console output
    print(f"[+] Collecting console output...")
    try:
        console_response = ec2_client.get_console_output(InstanceId=instance_id)
        all_data["ConsoleOutput"] = console_response
        if console_response.get("Output"):
            print(f"    ✓ Collected console output")
        else:
            print(f"    ⚠ No console output available")
    except Exception as e:
        print(f"    ⚠ Error collecting console output: {e} (continuing)")
    
    # 5. IAM instance profile
    print(f"[+] Collecting IAM instance profile...")
    try:
        if all_data["InstanceInfo"]:
            iam_profile_arn = all_data["InstanceInfo"].get("IamInstanceProfile", {}).get("Arn")
            if iam_profile_arn:
                profile_name = iam_profile_arn.split("/")[-1]
                profile_response = iam_client.get_instance_profile(InstanceProfileName=profile_name)
                all_data["IamProfile"] = profile_response.get("InstanceProfile", {})
                print(f"    ✓ Collected IAM profile")
            else:
                print(f"    ⚠ No IAM instance profile attached")
    except Exception as e:
        print(f"    ⚠ Error collecting IAM profile: {e} (continuing)")
    
    # 6. Network interfaces
    print(f"[+] Collecting network interfaces...")
    try:
        if all_data["InstanceInfo"]:
            all_data["NetworkInterfaces"] = all_data["InstanceInfo"].get("NetworkInterfaces", [])
            print(f"    ✓ Collected {len(all_data['NetworkInterfaces'])} network interface(s)")
    except Exception as e:
        print(f"    ⚠ Error collecting network interfaces: {e} (continuing)")
    
    # 7. Create summary
    try:
        if all_data["InstanceInfo"]:
            all_data["Summary"] = _extract_instance_summary(all_data["InstanceInfo"])
    except Exception as e:
        print(f"    ⚠ Error creating summary: {e} (continuing)")
    
    # Save combined file
    instance_id_clean = instance_id.replace("i-", "")
    filename = f"ec2_{instance_id_clean}_all.json"
    filepath = _save_json_file(output_dir, filename, all_data)
    if filepath:
        print(f"\n[✓] Saved all EC2 data → {filepath}\n")

