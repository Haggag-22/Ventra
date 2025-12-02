import os
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_ec2_client(region):
    """
    EC2 client using Ventra's internal credentials.
    """
    profile_name, creds = get_active_profile()

    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("ec2")


def _get_iam_client(region):
    """
    IAM client using Ventra's internal credentials.
    """
    profile_name, creds = get_active_profile()

    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("iam")


def _extract_instance_summary(instance_data):
    """
    Extract key metadata from instance data for summary.
    """
    summary = {
        "InstanceId": instance_data.get("InstanceId"),
        "InstanceType": instance_data.get("InstanceType"),
        "State": instance_data.get("State", {}).get("Name"),
        "LaunchTime": str(instance_data.get("LaunchTime", "")),
        "ImageId": instance_data.get("ImageId"),
        "KeyName": instance_data.get("KeyName"),
        "VpcId": instance_data.get("VpcId"),
        "SubnetId": instance_data.get("SubnetId"),
        "PrivateIpAddress": instance_data.get("PrivateIpAddress"),
        "PublicIpAddress": instance_data.get("PublicIpAddress"),
        "PrivateDnsName": instance_data.get("PrivateDnsName"),
        "PublicDnsName": instance_data.get("PublicDnsName"),
        "SecurityGroups": [
            {
                "GroupId": sg.get("GroupId"),
                "GroupName": sg.get("GroupName"),
            }
            for sg in instance_data.get("SecurityGroups", [])
        ],
        "IamInstanceProfile": instance_data.get("IamInstanceProfile"),
        "Tags": instance_data.get("Tags", []),
        "NetworkInterfaces": [
            {
                "NetworkInterfaceId": ni.get("NetworkInterfaceId"),
                "PrivateIpAddress": ni.get("PrivateIpAddress"),
                "PublicIp": ni.get("Association", {}).get("PublicIp"),
                "SubnetId": ni.get("SubnetId"),
                "VpcId": ni.get("VpcId"),
                "Groups": ni.get("Groups", []),
            }
            for ni in instance_data.get("NetworkInterfaces", [])
        ],
        "BlockDeviceMappings": [
            {
                "DeviceName": bdm.get("DeviceName"),
                "Ebs": bdm.get("Ebs", {}).get("VolumeId"),
            }
            for bdm in instance_data.get("BlockDeviceMappings", [])
        ],
    }
    return summary


def _collect_instance_metadata(ec2_client, iam_client, instance_id, output_dir):
    """
    Collect all metadata for a single EC2 instance.
    Returns dict with all collected data.
    """
    instance_results = {
        "instance_id": instance_id,
        "describe_instances": None,
        "volumes": None,
        "console_output": None,
        "iam_profile": None,
        "network_interfaces": None,
        "summary": None,
    }

    # -----------------------------------------------------------
    # 1. Describe Instances
    # -----------------------------------------------------------
    try:
        print(f"  [+] Describing instance: {instance_id}")
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response.get("Reservations"):
            print(f"  ❌ Instance {instance_id} not found")
            return None
        
        instance_data = response["Reservations"][0]["Instances"][0]
        instance_results["describe_instances"] = instance_data

        print(f"    ✓ Collected: describe_instances")

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "InvalidInstanceID.NotFound":
            print(f"  ❌ Instance {instance_id} not found")
        else:
            print(f"  ❌ Error describing instance {instance_id}: {e}")
        return None
    except Exception as e:
        print(f"  ❌ Unexpected error describing instance {instance_id}: {e}")
        return None

    # -----------------------------------------------------------
    # 2. Describe Volumes (filtered by instance ID)
    # -----------------------------------------------------------
    try:
        print(f"  [+] Collecting volumes for: {instance_id}")
        volumes_response = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
        )
        instance_results["volumes"] = volumes_response.get("Volumes", [])

        print(f"    ✓ Collected: {len(instance_results['volumes'])} volumes")

    except ClientError as e:
        print(f"  ⚠ Failed to collect volumes for {instance_id}: {e}")
    except Exception as e:
        print(f"  ⚠ Unexpected error collecting volumes for {instance_id}: {e}")

    # -----------------------------------------------------------
    # 3. Get Console Output
    # -----------------------------------------------------------
    try:
        print(f"  [+] Collecting console output for: {instance_id}")
        console_response = ec2_client.get_console_output(InstanceId=instance_id)
        instance_results["console_output"] = console_response
        
        if console_response.get("Output"):
            print(f"    ✓ Collected: console output ({len(console_response.get('Output', ''))} chars)")
        else:
            print(f"    ⚠ No console output available (instance may be stopped)")

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "InvalidInstanceID.NotFound":
            print(f"    ⚠ Console output not available: instance not found")
        else:
            print(f"    ⚠ Console output not available: {e}")
    except Exception as e:
        print(f"    ⚠ Error collecting console output: {e}")

    # -----------------------------------------------------------
    # 4. IAM Instance Profile (if attached)
    # -----------------------------------------------------------
    try:
        iam_profile_arn = instance_data.get("IamInstanceProfile", {}).get("Arn")

        if iam_profile_arn:
            print(f"  [+] Collecting IAM instance profile for: {instance_id}")
            # Extract profile name from ARN: arn:aws:iam::123456789012:instance-profile/ProfileName
            profile_name = iam_profile_arn.split("/")[-1]

            try:
                profile_response = iam_client.get_instance_profile(InstanceProfileName=profile_name)
                instance_results["iam_profile"] = profile_response.get("InstanceProfile", {})
                
                print(f"    ✓ Collected: IAM instance profile ({profile_name})")
            except ClientError as e:
                print(f"    ⚠ Failed to get IAM profile {profile_name}: {e}")
        else:
            print(f"  [+] No IAM instance profile attached to: {instance_id}")

    except Exception as e:
        print(f"  ⚠ Error checking IAM profile: {e}")

    # -----------------------------------------------------------
    # 5. Network Interfaces (extracted from instance data)
    # -----------------------------------------------------------
    try:
        network_interfaces = instance_data.get("NetworkInterfaces", [])
        instance_results["network_interfaces"] = network_interfaces

        print(f"    ✓ Collected: {len(network_interfaces)} network interfaces")

    except Exception as e:
        print(f"  ⚠ Error extracting network interfaces: {e}")

    # -----------------------------------------------------------
    # 6. Create Summary
    # -----------------------------------------------------------
    try:
        instance_results["summary"] = _extract_instance_summary(instance_data)
    except Exception as e:
        print(f"  ⚠ Error creating summary: {e}")

    return instance_results


def run_ec2_meta_external(args):
    """
    Collect EC2 metadata passively for one or more instances.
    Uses AWS APIs without touching the instances (non-intrusive).
    """
    print("[+] EC2 Passive Metadata Collector")
    print(f"    Instances:  {', '.join(args.instance)}")
    print(f"    Region:     {args.region}")
    
    # Get output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    else:
        output_dir = args.output or "/Users/omar/Desktop/Ventra/output"
    
    output_dir = os.path.join(output_dir, "resources")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"    Output:     {output_dir}\n")
    
    # Get AWS clients
    try:
        ec2_client = _get_ec2_client(args.region)
        iam_client = _get_iam_client(args.region)
    except Exception as e:
        print(f"❌ Error getting AWS clients: {e}")
        return
    
    # Collect metadata for each instance
    all_results = []
    successful_instances = []
    failed_instances = []
    
    for instance_id in args.instance:
        print(f"\n[+] Processing instance: {instance_id}")
        print("=" * 60)
        
        result = _collect_instance_metadata(ec2_client, iam_client, instance_id, None)
        
        if result:
            all_results.append(result)
            successful_instances.append(instance_id)
        else:
            failed_instances.append(instance_id)

        print("=" * 60)
    
    # Create combined summary file
    if all_results:
        summary_data = {
            "collection_timestamp": datetime.utcnow().isoformat() + "Z",
            "total_instances": len(args.instance),
            "successful": len(successful_instances),
            "failed": len(failed_instances),
            "successful_instance_ids": successful_instances,
            "failed_instance_ids": failed_instances,
            "instances": all_results,
        }
        
        summary_path = os.path.join(output_dir, "ec2_passive_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, default=str)
        
        print(f"\n[✓] Collection complete")
        print(f"    Successful: {len(successful_instances)} instance(s)")
        if failed_instances:
            print(f"    Failed: {len(failed_instances)} instance(s): {', '.join(failed_instances)}")
        print(f"    Summary saved: {summary_path}\n")
    else:
        print(f"\n❌ No instances were successfully collected.\n")

