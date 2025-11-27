import os
import json
import time
import boto3
import paramiko
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


def _wait_for_snapshot_completion(ec2_client, snapshot_id, max_wait_minutes=60):
    """
    Wait for a snapshot to reach 'completed' state.
    Returns: snapshot data dict or None if failed/timed out
    """
    print(f"    [⏳] Waiting for snapshot {snapshot_id} to complete...")
    
    start_time = time.time()
    max_wait_seconds = max_wait_minutes * 60
    check_interval = 10  # Check every 10 seconds
    
    last_progress = 0
    
    while True:
        elapsed = time.time() - start_time
        
        if elapsed > max_wait_seconds:
            print(f"    ❌ Snapshot {snapshot_id} timed out after {max_wait_minutes} minutes")
            return None
        
        try:
            response = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
            if not response.get("Snapshots"):
                print(f"    ❌ Snapshot {snapshot_id} not found")
                return None
            
            snapshot = response["Snapshots"][0]
            state = snapshot.get("State", "unknown")
            progress = snapshot.get("Progress", "0%")
            
            # Print progress updates
            if progress != last_progress:
                print(f"      Progress: {progress} (State: {state})")
                last_progress = progress
            
            if state == "completed":
                print(f"    ✓ Snapshot {snapshot_id} completed")
                return snapshot
            elif state == "error":
                print(f"    ❌ Snapshot {snapshot_id} failed with error state")
                return None
            
            # Wait before next check
            time.sleep(check_interval)
            
        except ClientError as e:
            print(f"    ❌ Error checking snapshot status: {e}")
            return None
        except Exception as e:
            print(f"    ❌ Unexpected error checking snapshot: {e}")
            return None


def _extract_snapshot_metadata(snapshot_data):
    """
    Extract key metadata from snapshot data.
    """
    metadata = {
        "SnapshotId": snapshot_data.get("SnapshotId"),
        "VolumeId": snapshot_data.get("VolumeId"),
        "VolumeSize": snapshot_data.get("VolumeSize"),
        "StartTime": str(snapshot_data.get("StartTime", "")),
        "Progress": snapshot_data.get("Progress", "0%"),
        "State": snapshot_data.get("State"),
        "Encrypted": snapshot_data.get("Encrypted", False),
        "KmsKeyId": snapshot_data.get("KmsKeyId"),
        "Description": snapshot_data.get("Description"),
        "Tags": snapshot_data.get("Tags", []),
        "OwnerId": snapshot_data.get("OwnerId"),
        "OwnerAlias": snapshot_data.get("OwnerAlias"),
    }
    return metadata


def run_ec2_snapshots(args):
    """
    Create snapshots for volumes attached to an EC2 instance, OR collect metadata for existing snapshots.
    This collector can create immutable forensic artifacts or collect metadata from existing snapshots.
    """
    print("[+] EC2 Snapshots Collector")
    print(f"    Region:     {args.region}")
    
    # Determine collection mode: create new snapshots or collect existing ones
    snapshot_ids = []
    instance_id = None
    collection_mode = None
    
    if hasattr(args, "instance") and args.instance:
        # Mode 1: Create new snapshots from instance volumes
        instance_id = args.instance
        collection_mode = "create"
        print(f"    Mode:       Create new snapshots")
        print(f"    Instance:   {instance_id}")
        print("    ⚠ WARNING: This will create new snapshots in AWS.")
        print("    ⚠ Snapshots are immutable forensic artifacts.\n")
    elif hasattr(args, "snapshots") and args.snapshots:
        # Mode 2: Collect metadata for existing snapshots (comma-separated)
        snapshot_ids = [s.strip() for s in args.snapshots.split(",") if s.strip()]
        collection_mode = "collect"
        print(f"    Mode:       Collect existing snapshots")
        print(f"    Snapshots:  {', '.join(snapshot_ids)}\n")
    elif hasattr(args, "snapshot") and args.snapshot:
        # Mode 3: Collect metadata for single existing snapshot
        snapshot_ids = [args.snapshot]
        collection_mode = "collect"
        print(f"    Mode:       Collect existing snapshot")
        print(f"    Snapshot:   {args.snapshot}\n")
    else:
        print(f"❌ Must specify either --instance (create new), --snapshot, or --snapshots (collect existing)")
        return
    
    # Get case directory
    from ventra.case.store import get_case_dir, create_case
    case_dir = get_case_dir(args.case)
    if not case_dir:
        print(f"[+] Case '{args.case}' not found, creating new case...")
        _, case_dir = create_case(args.case)
    
    # Output goes directly to case directory (no subdirectories)
    print(f"    Output:     {case_dir}\n")
    
    # Get EC2 client
    try:
        ec2_client = _get_ec2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting EC2 client: {e}")
        return
    
    # Process based on mode
    if collection_mode == "create":
        # MODE: Create new snapshots from instance volumes
        # Step 1: Describe instance to verify it exists
        try:
            print(f"[+] Describing instance: {instance_id}")
            instance_response = ec2_client.describe_instances(InstanceIds=[instance_id])
            
            if not instance_response.get("Reservations"):
                print(f"❌ Instance {instance_id} not found")
                return
            
            instance_data = instance_response["Reservations"][0]["Instances"][0]
            block_device_mappings = instance_data.get("BlockDeviceMappings", [])
            
            print(f"    ✓ Found {len(block_device_mappings)} volume attachment(s)\n")
            
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
            print(f"[+] Enumerating attached volumes...")
            volumes_response = ec2_client.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
            )
            volumes = volumes_response.get("Volumes", [])
            
            if not volumes:
                print(f"    ⚠ No volumes found attached to instance {instance_id}")
                return
            
            print(f"    ✓ Found {len(volumes)} volume(s) to snapshot\n")
            
        except ClientError as e:
            print(f"❌ Error describing volumes: {e}")
            return
        except Exception as e:
            print(f"❌ Unexpected error describing volumes: {e}")
            return
        
        # Step 3: Create snapshots for each volume
        snapshots_summary = []
        successful_snapshots = []
        failed_snapshots = []
        
        for idx, volume in enumerate(volumes, 1):
            volume_id = volume.get("VolumeId")
            volume_size = volume.get("Size", 0)
            
            print(f"[{idx}/{len(volumes)}] Processing volume: {volume_id}")
            print(f"    Size: {volume_size} GB")
            
            # Create snapshot description
            snapshot_description = f"Ventra DFIR snapshot for instance {instance_id}, volume {volume_id} - {datetime.utcnow().isoformat()}Z"
            
            # Create snapshot
            try:
                print(f"    [+] Creating snapshot...")
                create_response = ec2_client.create_snapshot(
                    VolumeId=volume_id,
                    Description=snapshot_description,
                    TagSpecifications=[
                        {
                            "ResourceType": "snapshot",
                            "Tags": [
                                {"Key": "VentraDFIR", "Value": "true"},
                                {"Key": "InstanceId", "Value": instance_id},
                                {"Key": "VolumeId", "Value": volume_id},
                                {"Key": "CreatedBy", "Value": "Ventra"},
                            ]
                        }
                    ]
                )
                
                snapshot_id = create_response.get("SnapshotId")
                print(f"    ✓ Snapshot created: {snapshot_id}")
                
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                print(f"    ❌ Failed to create snapshot for volume {volume_id}: {e}")
                failed_snapshots.append({
                    "volume_id": volume_id,
                    "error": str(e),
                    "error_code": error_code,
                })
                continue
            except Exception as e:
                print(f"    ❌ Unexpected error creating snapshot: {e}")
                failed_snapshots.append({
                    "volume_id": volume_id,
                    "error": str(e),
                })
                continue
            
            # Wait for snapshot to complete
            snapshot_data = _wait_for_snapshot_completion(ec2_client, snapshot_id)
            
            if not snapshot_data:
                print(f"    ❌ Snapshot {snapshot_id} did not complete successfully")
                failed_snapshots.append({
                    "volume_id": volume_id,
                    "snapshot_id": snapshot_id,
                    "error": "Snapshot did not complete",
                })
                continue
            
            # Extract metadata
            snapshot_metadata = _extract_snapshot_metadata(snapshot_data)
            
            # Prepare snapshot data with full details
            snapshot_entry = {
                "snapshot_id": snapshot_id,
                "snapshot_metadata": snapshot_metadata,
                "snapshot_full_data": snapshot_data,  # Include full snapshot data
                "artifacts": None,
            }
            
            # Automatically extract artifacts (use original instance if available)
            print(f"  [+] Extracting artifacts from snapshot...")
            try:
                from ventra.collector.ec2.artifact_extraction import extract_artifacts_from_snapshot_auto
                artifact_result = extract_artifacts_from_snapshot_auto(
                    ec2_client=ec2_client,
                    snapshot_id=snapshot_id,
                    original_instance_id=instance_id if collection_mode == "create" else None,
                    case_dir=case_dir,
                )
                
                # Store artifact results in snapshot entry
                snapshot_entry["artifacts"] = artifact_result.get("artifacts")
                
                if artifact_result.get("artifacts"):
                    artifact_count = len(artifact_result["artifacts"].get("artifacts_content", {}))
                    print(f"    ✓ Artifacts extracted: {artifact_count} artifact(s)")
                elif artifact_result.get("errors"):
                    print(f"    ⚠ Artifact extraction skipped: {', '.join(artifact_result['errors'])}")
                    snapshot_entry["artifact_errors"] = artifact_result.get("errors")
            except Exception as e:
                print(f"    ⚠ Artifact extraction skipped: {e}")
                snapshot_entry["artifact_errors"] = [str(e)]
            
            # Add to summary
            snapshots_summary.append(snapshot_entry)
            successful_snapshots.append(snapshot_id)
            
            print()
        
        # Save summary for create mode (after loop completes) - includes all data + artifacts
        summary_data = {
            "collection_timestamp": datetime.utcnow().isoformat() + "Z",
            "collection_mode": "create",
            "instance_id": instance_id,
            "total_volumes": len(volumes),
            "successful_snapshots": len(successful_snapshots),
            "failed_snapshots": len(failed_snapshots),
            "snapshot_ids": successful_snapshots,
            "snapshots": snapshots_summary,  # Includes full snapshot data + artifacts
            "failures": failed_snapshots if failed_snapshots else None,
        }
    
    else:
        # MODE: Collect metadata for existing snapshots
        print(f"[+] Collecting metadata for {len(snapshot_ids)} existing snapshot(s)...")
        snapshots_summary = []
        successful_snapshots = []
        failed_snapshots = []
        
        for idx, snapshot_id in enumerate(snapshot_ids, 1):
            print(f"[{idx}/{len(snapshot_ids)}] Processing snapshot: {snapshot_id}")
            
            try:
                # Describe snapshot
                response = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
                if not response.get("Snapshots"):
                    print(f"    ❌ Snapshot {snapshot_id} not found")
                    failed_snapshots.append({
                        "snapshot_id": snapshot_id,
                        "error": "Snapshot not found"
                    })
                    continue
                
                snapshot_data = response["Snapshots"][0]
                
                # Extract metadata
                snapshot_metadata = _extract_snapshot_metadata(snapshot_data)
                
                # Prepare snapshot data with full details
                snapshot_entry = {
                    "snapshot_id": snapshot_id,
                    "snapshot_metadata": snapshot_metadata,
                    "snapshot_full_data": snapshot_data,  # Include full snapshot data
                    "artifacts": None,
                }
                
                # Automatically extract artifacts
                print(f"  [+] Extracting artifacts from snapshot...")
                try:
                    from ventra.collector.ec2.artifact_extraction import extract_artifacts_from_snapshot_auto
                    artifact_result = extract_artifacts_from_snapshot_auto(
                        ec2_client=ec2_client,
                        snapshot_id=snapshot_id,
                        original_instance_id=None,  # No instance ID for collect mode
                        case_dir=case_dir,
                    )
                    
                    # Store artifact results in snapshot entry
                    snapshot_entry["artifacts"] = artifact_result.get("artifacts")
                    
                    if artifact_result.get("artifacts"):
                        artifact_count = len(artifact_result["artifacts"].get("artifacts_content", {}))
                        print(f"    ✓ Artifacts extracted: {artifact_count} artifact(s)")
                    elif artifact_result.get("errors"):
                        print(f"    ⚠ Artifact extraction skipped: {', '.join(artifact_result['errors'])}")
                        snapshot_entry["artifact_errors"] = artifact_result.get("errors")
                except Exception as e:
                    print(f"    ⚠ Artifact extraction skipped: {e}")
                    snapshot_entry["artifact_errors"] = [str(e)]
                
                # Add to summary
                snapshots_summary.append(snapshot_entry)
                successful_snapshots.append(snapshot_id)
                
                # Print key details
                print(f"      Volume: {snapshot_metadata['VolumeId']}")
                print(f"      Size: {snapshot_metadata['VolumeSize']} GB")
                print(f"      State: {snapshot_metadata['State']}")
                print(f"      Encrypted: {snapshot_metadata['Encrypted']}")
                print()
                
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                print(f"    ❌ Error describing snapshot {snapshot_id}: {e}")
                failed_snapshots.append({
                    "snapshot_id": snapshot_id,
                    "error": str(e),
                    "error_code": error_code,
                })
                continue
            except Exception as e:
                print(f"    ❌ Unexpected error: {e}")
                failed_snapshots.append({
                    "snapshot_id": snapshot_id,
                    "error": str(e),
                })
                continue
        
        # Save summary for collect mode - includes all data + artifacts
        summary_data = {
            "collection_timestamp": datetime.utcnow().isoformat() + "Z",
            "collection_mode": "collect",
            "snapshot_ids_requested": snapshot_ids,
            "successful_snapshots": len(successful_snapshots),
            "failed_snapshots": len(failed_snapshots),
            "snapshot_ids": successful_snapshots,
            "snapshots": snapshots_summary,  # Includes full snapshot data + artifacts
            "failures": failed_snapshots if failed_snapshots else None,
        }
    
    # Step 4: Save single comprehensive summary file (directly in case directory)
    summary_path = os.path.join(case_dir, "ec2_snapshots_summary.json")
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, default=str)
        
        print(f"[✓] Collection complete")
        if collection_mode == "create":
            print(f"    Total volumes: {len(volumes)}")
        print(f"    Successful snapshots: {summary_data.get('successful_snapshots', 0)}")
        if summary_data.get("failed_snapshots", 0) > 0:
            print(f"    Failed snapshots: {summary_data.get('failed_snapshots', 0)}")
        print(f"    Summary saved: {summary_path}\n")
    except Exception as e:
        print(f"❌ Error saving summary file: {e}\n")

