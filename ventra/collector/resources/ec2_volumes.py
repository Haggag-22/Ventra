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


def _extract_volume_metadata(volume_data):
    """
    Extract key metadata from volume data.
    """
    metadata = {
        "VolumeId": volume_data.get("VolumeId"),
        "Size": volume_data.get("Size"),
        "VolumeType": volume_data.get("VolumeType"),
        "State": volume_data.get("State"),
        "AvailabilityZone": volume_data.get("AvailabilityZone"),
        "CreateTime": str(volume_data.get("CreateTime", "")),
        "Encrypted": volume_data.get("Encrypted", False),
        "KmsKeyId": volume_data.get("KmsKeyId"),
        "Attachments": volume_data.get("Attachments", []),
        "Tags": volume_data.get("Tags", []),
        "Iops": volume_data.get("Iops"),
        "Throughput": volume_data.get("Throughput"),
        "SnapshotId": volume_data.get("SnapshotId"),
        "MultiAttachEnabled": volume_data.get("MultiAttachEnabled", False),
    }
    return metadata


def run_ec2_volumes(args):
    """
    Collect EBS volume metadata.
    Can collect by instance (all attached volumes) or by specific volume ID(s).
    This is a metadata-only collector (non-intrusive).
    """
    print("[+] EC2 Volumes Collector")
    print(f"    Region:     {args.region}")
    
    # Get case directory
    from ventra.case.store import get_case_dir, create_case
    case_dir = get_case_dir(args.case)
    if not case_dir:
        print(f"[+] Case '{args.case}' not found, creating new case...")
        _, case_dir = create_case(args.case)
    
    # Get EC2 client
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    # Determine collection mode: instance-based or volume-based
    volume_ids = []
    instance_id = None
    collection_mode = None
    
    if hasattr(args, "instance") and args.instance:
        # Mode 1: Collect all volumes attached to an instance
        instance_id = args.instance
        collection_mode = "instance"
        print(f"    Mode:       Instance-based")
        print(f"    Instance:   {instance_id}")
    elif hasattr(args, "volumes") and args.volumes:
        # Mode 2: Collect specific volumes (comma-separated)
        volume_ids = [v.strip() for v in args.volumes.split(",") if v.strip()]
        collection_mode = "volumes"
        print(f"    Mode:       Volume-based")
        print(f"    Volumes:    {', '.join(volume_ids)}")
    elif hasattr(args, "volume") and args.volume:
        # Mode 3: Collect single volume
        volume_ids = [args.volume]
        collection_mode = "volumes"
        print(f"    Mode:       Volume-based")
        print(f"    Volume:     {args.volume}")
    else:
        print(f"❌ Must specify either --instance, --volume, or --volumes")
        return
    
    # Output goes to resources subdirectory
    case_dir = os.path.join(case_dir, "resources")
    os.makedirs(case_dir, exist_ok=True)
    print(f"    Output:     {case_dir}\n")
    
    # Collect volumes based on mode
    volumes = []
    
    if collection_mode == "instance":
        # Step 1: Describe instance to verify it exists
        try:
            print(f"[+] Describing instance: {instance_id}")
            instance_response = ec2_client.describe_instances(InstanceIds=[instance_id])
            
            if not instance_response.get("Reservations"):
                print(f"❌ Instance {instance_id} not found")
                return
            
            instance_data = instance_response["Reservations"][0]["Instances"][0]
            block_device_mappings = instance_data.get("BlockDeviceMappings", [])
            
            print(f"    ✓ Found {len(block_device_mappings)} volume attachment(s)")
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "InvalidInstanceID.NotFound":
                print(f"❌ Instance {instance_id} not found")
            else:
                print(f"❌ Error describing instance {instance_id}: {e}")
            return
        except Exception as e:
            print(f"❌ Unexpected error describing instance {instance_id}: {e}")
            return
        
        # Step 2: Get all volumes attached to this instance
        try:
            print(f"[+] Collecting volume metadata...")
            volumes_response = ec2_client.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
            )
            volumes = volumes_response.get("Volumes", [])
            
            if not volumes:
                print(f"    ⚠ No volumes found attached to instance {instance_id}")
                return
            
            print(f"    ✓ Found {len(volumes)} volume(s)\n")
            
        except ClientError as e:
            print(f"❌ Error describing volumes: {e}")
            return
        except Exception as e:
            print(f"❌ Unexpected error describing volumes: {e}")
            return
    
    else:
        # Mode: Direct volume ID(s)
        try:
            print(f"[+] Collecting volume metadata for {len(volume_ids)} volume(s)...")
            volumes_response = ec2_client.describe_volumes(VolumeIds=volume_ids)
            volumes = volumes_response.get("Volumes", [])
            
            if not volumes:
                print(f"    ⚠ No volumes found")
                return
            
            print(f"    ✓ Found {len(volumes)} volume(s)\n")
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "InvalidVolume.NotFound":
                print(f"❌ One or more volumes not found")
            else:
                print(f"❌ Error describing volumes: {e}")
            return
        except Exception as e:
            print(f"❌ Unexpected error describing volumes: {e}")
            return
    
    # Step 3: Collect all data (volumes + artifacts) for summary
    volumes_data = []
    
    for volume in volumes:
        volume_id = volume.get("VolumeId")
        print(f"[+] Processing volume: {volume_id}")
        
        # Prepare volume data with full details
        volume_data = {
            "volume_id": volume_id,
            "volume_metadata": _extract_volume_metadata(volume),
            "volume_full_data": volume,  # Include full volume data
            "artifacts": None,
            "snapshot_id": None,
        }
        
        # Print key details
        device_name = ""
        if volume.get("Attachments"):
            device_name = volume["Attachments"][0].get("Device", "N/A")
        
        print(f"      Size: {volume_metadata['Size']} GB")
        print(f"      Type: {volume_metadata['VolumeType']}")
        print(f"      Device: {device_name}")
        print(f"      Encrypted: {volume_metadata['Encrypted']}")
        print(f"      AZ: {volume_metadata['AvailabilityZone']}")
        
        # Automatically create snapshot and extract artifacts
        print(f"  [+] Creating snapshot and extracting artifacts...")
        try:
            # First create snapshot
            snapshot_description = f"Ventra DFIR snapshot for artifact extraction - {datetime.utcnow().isoformat()}Z"
            create_response = ec2_client.create_snapshot(
                VolumeId=volume_id,
                Description=snapshot_description,
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "VentraDFIR", "Value": "true"},
                            {"Key": "VolumeId", "Value": volume_id},
                            {"Key": "CreatedBy", "Value": "Ventra"},
                        ]
                    }
                ]
            )
            
            snapshot_id = create_response.get("SnapshotId")
            print(f"    ✓ Snapshot created: {snapshot_id}")
            
            # Wait for snapshot to complete
            from ventra.collector.ec2.ec2_snapshots import _wait_for_snapshot_completion
            snapshot_data = _wait_for_snapshot_completion(ec2_client, snapshot_id)
            
            if snapshot_data:
                # Extract artifacts automatically
                from ventra.collector.ec2.artifact_extraction import extract_artifacts_from_snapshot_auto
                # Determine instance_id for artifact extraction
                artifact_instance_id = None
                if collection_mode == "instance":
                    artifact_instance_id = instance_id
                elif collection_mode == "volumes" and hasattr(args, "instance") and args.instance:
                    artifact_instance_id = args.instance
                
                artifact_result = extract_artifacts_from_snapshot_auto(
                    ec2_client=ec2_client,
                    snapshot_id=snapshot_id,
                    original_instance_id=artifact_instance_id,
                    case_dir=case_dir,
                )
                
                # Store artifact results in volume data
                volume_data["snapshot_id"] = snapshot_id
                volume_data["artifacts"] = artifact_result.get("artifacts")
                
                if artifact_result.get("artifacts"):
                    artifact_count = len(artifact_result["artifacts"].get("artifacts_content", {}))
                    print(f"    ✓ Artifacts extracted: {artifact_count} artifact(s)")
                elif artifact_result.get("errors"):
                    print(f"    ⚠ Artifact extraction skipped: {', '.join(artifact_result['errors'])}")
                    volume_data["artifact_errors"] = artifact_result.get("errors")
            else:
                print(f"    ⚠ Snapshot did not complete, skipping artifact extraction")
        except Exception as e:
            print(f"    ⚠ Artifact extraction skipped: {e}")
            volume_data["artifact_errors"] = [str(e)]
        
        volumes_data.append(volume_data)
        print()
    
    # Step 4: Save single comprehensive summary file
    summary_data = {
        "collection_timestamp": datetime.utcnow().isoformat() + "Z",
        "collection_mode": collection_mode,
        "instance_id": instance_id if collection_mode == "instance" else None,
        "volume_ids": volume_ids if collection_mode == "volumes" else None,
        "total_volumes": len(volumes_data),
        "volumes": volumes_data,  # Includes full volume data + artifacts
    }
    
    # Save directly in case directory (no subdirectories)
    summary_path = os.path.join(case_dir, "ec2_volumes_summary.json")
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, default=str)
        
        print(f"[✓] Collection complete")
        print(f"    Total volumes: {len(volumes_summary)}")
        print(f"    Summary saved: {summary_path}\n")
    except Exception as e:
        print(f"❌ Error saving summary file: {e}\n")

