"""
EC2 All Collector
Collects all EC2 instance information (metadata, volumes, snapshots) into a single combined file.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile
from ventra.collector.resources.ec2.ec2_metadata_passive import _extract_instance_summary


def _resolve_output_dir(args):
    """Resolve output directory and ensure resources/ subdir exists."""
    if hasattr(args, "case_dir") and args.case_dir:
        output_base = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_base = args.output
    else:
        output_base = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")

    output_dir = os.path.join(output_base, "resources")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


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


def _list_all_instance_ids(ec2_client) -> list:
    """Enumerate all EC2 instance IDs in the current region."""
    instance_ids = []
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                iid = inst.get("InstanceId")
                if iid:
                    instance_ids.append(iid)
    return instance_ids


def _collect_for_instance(ec2_client, iam_client, instance_id: str) -> dict:
    """Collect all EC2 instance data for a single instance ID."""
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
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if response.get("Reservations"):
            instance_data = response["Reservations"][0]["Instances"][0]
            all_data["InstanceInfo"] = instance_data
        else:
            all_data["error"] = f"Instance {instance_id} not found"
            return all_data
    except Exception as e:
        all_data["error"] = f"describe_instances failed: {e}"
        return all_data

    # 2. Collect volumes
    try:
        volumes_response = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
        )
        all_data["Volumes"] = volumes_response.get("Volumes", [])
    except Exception as e:
        all_data["volumes_error"] = str(e)

    # 3. Collect snapshots for volumes
    try:
        volume_ids = [v.get("VolumeId") for v in all_data["Volumes"] if v.get("VolumeId")]
        if volume_ids:
            snapshots_response = ec2_client.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": volume_ids}]
            )
            all_data["Snapshots"] = snapshots_response.get("Snapshots", [])
    except Exception as e:
        all_data["snapshots_error"] = str(e)

    # 4. Console output
    try:
        all_data["ConsoleOutput"] = ec2_client.get_console_output(InstanceId=instance_id)
    except Exception as e:
        all_data["console_output_error"] = str(e)

    # 5. IAM instance profile
    try:
        iam_profile_arn = all_data["InstanceInfo"].get("IamInstanceProfile", {}).get("Arn")
        if iam_profile_arn:
            profile_name = iam_profile_arn.split("/")[-1]
            profile_response = iam_client.get_instance_profile(InstanceProfileName=profile_name)
            all_data["IamProfile"] = profile_response.get("InstanceProfile", {})
    except Exception as e:
        all_data["iam_profile_error"] = str(e)

    # 6. Network interfaces
    try:
        all_data["NetworkInterfaces"] = all_data["InstanceInfo"].get("NetworkInterfaces", [])
    except Exception as e:
        all_data["network_interfaces_error"] = str(e)

    # 7. Summary
    try:
        all_data["Summary"] = _extract_instance_summary(all_data["InstanceInfo"])
    except Exception as e:
        all_data["summary_error"] = str(e)

    return all_data


def run_ec2_all(args):
    """Collect all EC2 instance data into a single file."""
    instance_arg = getattr(args, "instance", None)
    
    print(f"[+] EC2 All Collector")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    output_dir = _resolve_output_dir(args)
    print(f"    Output:      {output_dir}\n")
    
    try:
        ec2_client = _get_ec2_client(args.region)
        iam_client = _get_iam_client(args.region)
    except Exception as e:
        print(f"❌ Error getting clients: {e}")
        return
    
    # Determine target instances
    if instance_arg:
        instance_ids = [s.strip() for s in str(instance_arg).split(",") if s.strip()]
        print(f"    Mode:        specific instance(s) ({len(instance_ids)})")
    else:
        print("    Mode:        ALL instances in account/region")
        instance_ids = _list_all_instance_ids(ec2_client)
        print(f"    ✓ Found {len(instance_ids)} instance(s)")

    results = []
    for idx, instance_id in enumerate(instance_ids, 1):
        print(f"[+] [{idx}/{len(instance_ids)}] Collecting: {instance_id}")
        results.append(_collect_for_instance(ec2_client, iam_client, instance_id))

    # Save combined file(s)
    if instance_arg and len(instance_ids) == 1:
        instance_id_clean = instance_ids[0].replace("i-", "")
        filename = f"ec2_{instance_id_clean}_all.json"
        payload = results[0]
    else:
        filename = "ec2_all.json"
        payload = {
            "region": args.region,
            "instances": results,
            "total_instances": len(results),
        }

    filepath = _save_json_file(output_dir, filename, payload)
    if filepath:
        print(f"\n[✓] Saved EC2 data → {filepath}\n")

