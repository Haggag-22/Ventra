"""
Shared artifact extraction functions for EC2 collectors.
Used by snapshots and volumes collectors to extract forensic artifacts.
"""
import os
import time
import paramiko
from botocore.exceptions import ClientError


def _execute_ssh_command(ssh_client, command, timeout=60):
    """Execute a command via SSH and return stdout, stderr, and exit code."""
    stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    stdout_text = stdout.read().decode("utf-8", errors="replace")
    stderr_text = stderr.read().decode("utf-8", errors="replace")
    return stdout_text, stderr_text, exit_code


def _wait_for_volume_available(ec2_client, volume_id, max_wait_minutes=5):
    """Wait for volume to be in 'available' state."""
    start_time = time.time()
    max_wait_seconds = max_wait_minutes * 60
    check_interval = 2
    
    while True:
        elapsed = time.time() - start_time
        if elapsed > max_wait_seconds:
            return False
        
        try:
            response = ec2_client.describe_volumes(VolumeIds=[volume_id])
            if response.get("Volumes"):
                state = response["Volumes"][0].get("State")
                if state == "available":
                    return True
                elif state == "error":
                    return False
        except Exception:
            pass
        
        time.sleep(check_interval)


def _wait_for_attachment(ec2_client, volume_id, instance_id, max_wait_minutes=5):
    """Wait for volume to be attached to instance. Returns device name."""
    start_time = time.time()
    max_wait_seconds = max_wait_minutes * 60
    check_interval = 2
    
    while True:
        elapsed = time.time() - start_time
        if elapsed > max_wait_seconds:
            return None
        
        try:
            response = ec2_client.describe_volumes(VolumeIds=[volume_id])
            if response.get("Volumes"):
                attachments = response["Volumes"][0].get("Attachments", [])
                for att in attachments:
                    if att.get("InstanceId") == instance_id and att.get("State") == "attached":
                        return att.get("Device")
        except Exception:
            pass
        
        time.sleep(check_interval)


def _detect_filesystem_type(ssh_client, device):
    """Detect filesystem type of a device."""
    cmd = f"sudo blkid -o value -s TYPE {device} 2>/dev/null || echo ''"
    stdout, stderr, exit_code = _execute_ssh_command(ssh_client, cmd)
    fs_type = stdout.strip().lower()
    
    if not fs_type:
        cmd = f"sudo file -s {device} 2>/dev/null | grep -oE '(ext[234]|xfs|ntfs|vfat|btrfs)' || echo 'unknown'"
        stdout, stderr, exit_code = _execute_ssh_command(ssh_client, cmd)
        fs_type = stdout.strip().lower()
    
    return fs_type if fs_type else "unknown"


def _mount_volume_readonly(ssh_client, device, mount_point):
    """Mount a volume read-only at the specified mount point."""
    _execute_ssh_command(ssh_client, f"sudo mkdir -p {mount_point}")
    
    fs_type = _detect_filesystem_type(ssh_client, device)
    print(f"      Filesystem: {fs_type}")
    
    if fs_type in ["ext2", "ext3", "ext4", "xfs", "btrfs"]:
        cmd = f"sudo mount -o ro,noexec,nosuid,nodev {device} {mount_point}"
    elif fs_type in ["ntfs", "vfat"]:
        cmd = f"sudo mount -t {fs_type} -o ro,noexec,nosuid,nodev {device} {mount_point}"
    else:
        cmd = f"sudo mount -o ro {device} {mount_point}"
    
    stdout, stderr, exit_code = _execute_ssh_command(ssh_client, cmd)
    
    if exit_code != 0:
        cmd = f"sudo mount -o ro {device} {mount_point}"
        stdout, stderr, exit_code = _execute_ssh_command(ssh_client, cmd)
    
    if exit_code != 0:
        return False, f"Mount failed: {stderr}"
    
    return True, mount_point


def _extract_linux_artifacts(ssh_client, mount_point):
    """Extract Linux forensic artifacts from mounted volume. Returns content in dict, not files."""
    artifacts = {
        "linux_artifacts": {},
        "artifacts_content": {},
        "errors": []
    }
    
    linux_paths = {
        "auth_log": "/var/log/auth.log",
        "secure_log": "/var/log/secure",
        "syslog": "/var/log/syslog",
        "messages": "/var/log/messages",
        "passwd": "/etc/passwd",
        "shadow": "/etc/shadow",
        "group": "/etc/group",
        "hosts": "/etc/hosts",
        "hostname": "/etc/hostname",
        "sshd_config": "/etc/ssh/sshd_config",
        "bash_history": "/root/.bash_history",
        "authorized_keys_root": "/root/.ssh/authorized_keys",
        "crontab_root": "/var/spool/cron/crontabs/root",
        "systemd_services": "/etc/systemd/system",
        "tmp_files": "/tmp",
        "var_tmp": "/var/tmp",
    }
    
    home_authorized_keys = []
    
    for artifact_name, artifact_path in linux_paths.items():
        full_path = os.path.join(mount_point, artifact_path.lstrip("/"))
        
        check_cmd = f"sudo test -e '{full_path}' && echo 'exists' || echo 'not_found'"
        stdout, stderr, exit_code = _execute_ssh_command(ssh_client, check_cmd)
        
        if "exists" in stdout:
            if artifact_name in ["passwd", "shadow", "group", "hosts", "hostname", "sshd_config", "authorized_keys_root"]:
                read_cmd = f"sudo cat '{full_path}' 2>/dev/null"
                stdout, stderr, exit_code = _execute_ssh_command(ssh_client, read_cmd)
                
                if exit_code == 0 and stdout:
                    # Store content in dict instead of saving file
                    artifacts["artifacts_content"][artifact_name] = stdout
                    artifacts["linux_artifacts"][artifact_name] = {
                        "path": artifact_path,
                        "extracted": True,
                        "size": len(stdout)
                    }
            
            elif artifact_name in ["tmp_files", "var_tmp", "systemd_services"]:
                list_cmd = f"sudo ls -la '{full_path}' 2>/dev/null | head -50"
                stdout, stderr, exit_code = _execute_ssh_command(ssh_client, list_cmd)
                
                if exit_code == 0:
                    # Store listing content in dict
                    artifacts["artifacts_content"][f"{artifact_name}_listing"] = stdout
                    artifacts["linux_artifacts"][artifact_name] = {
                        "path": artifact_path,
                        "extracted": True,
                        "listing": True
                    }
            
            elif artifact_name.endswith("_log"):
                read_cmd = f"sudo tail -1000 '{full_path}' 2>/dev/null"
                stdout, stderr, exit_code = _execute_ssh_command(ssh_client, read_cmd)
                
                if exit_code == 0 and stdout:
                    # Store log content in dict
                    artifacts["artifacts_content"][artifact_name] = stdout
                    artifacts["linux_artifacts"][artifact_name] = {
                        "path": artifact_path,
                        "extracted": True,
                        "lines": len(stdout.splitlines())
                    }
        else:
            artifacts["linux_artifacts"][artifact_name] = {
                "path": artifact_path,
                "extracted": False,
                "reason": "not_found"
            }
    
    search_cmd = f"sudo find {mount_point}/home -name 'authorized_keys' -type f 2>/dev/null | head -20"
    stdout, stderr, exit_code = _execute_ssh_command(ssh_client, search_cmd)
    
    if exit_code == 0 and stdout:
        for key_path in stdout.strip().split("\n"):
            if key_path:
                rel_path = key_path.replace(mount_point, "")
                read_cmd = f"sudo cat '{key_path}' 2>/dev/null"
                stdout_content, _, _ = _execute_ssh_command(ssh_client, read_cmd)
                
                if stdout_content:
                    # Store key content in dict
                    safe_name = rel_path.replace("/", "_").replace(".", "_")
                    artifacts["artifacts_content"][f"authorized_keys{safe_name}"] = stdout_content
                    home_authorized_keys.append(rel_path)
    
    if home_authorized_keys:
        artifacts["linux_artifacts"]["home_authorized_keys"] = home_authorized_keys
    
    return artifacts


def _extract_windows_artifacts(ssh_client, mount_point):
    """Extract Windows forensic artifacts from mounted volume. Returns content in dict, not files."""
    artifacts = {
        "windows_artifacts": {},
        "artifacts_content": {},
        "errors": []
    }
    
    windows_paths = {
        "system32": "/Windows/System32",
        "event_logs": "/Windows/System32/winevt/Logs",
        "prefetch": "/Windows/Prefetch",
        "programdata": "/ProgramData",
        "users": "/Users",
        "temp": "/Windows/Temp",
    }
    
    check_cmd = f"sudo test -d '{mount_point}/Windows' && echo 'windows' || echo 'not_windows'"
    stdout, stderr, exit_code = _execute_ssh_command(ssh_client, check_cmd)
    
    if "not_windows" in stdout:
        artifacts["errors"].append("Volume does not appear to be a Windows filesystem")
        return artifacts
    
    for artifact_name, artifact_path in windows_paths.items():
        full_path = os.path.join(mount_point, artifact_path.lstrip("/"))
        
        check_cmd = f"sudo test -e '{full_path}' && echo 'exists' || echo 'not_found'"
        stdout, stderr, exit_code = _execute_ssh_command(ssh_client, check_cmd)
        
        if "exists" in stdout:
            list_cmd = f"sudo ls -laR '{full_path}' 2>/dev/null | head -200"
            stdout, stderr, exit_code = _execute_ssh_command(ssh_client, list_cmd)
            
            if exit_code == 0 and stdout:
                # Store listing content in dict
                artifacts["artifacts_content"][f"windows_{artifact_name}_listing"] = stdout
                artifacts["windows_artifacts"][artifact_name] = {
                    "path": artifact_path,
                    "extracted": True,
                    "listing": True
                }
        else:
            artifacts["windows_artifacts"][artifact_name] = {
                "path": artifact_path,
                "extracted": False,
                "reason": "not_found"
            }
    
    registry_paths = [
        "/Windows/System32/config/SAM",
        "/Windows/System32/config/SYSTEM",
        "/Windows/System32/config/SOFTWARE",
    ]
    
    for reg_path in registry_paths:
        full_path = os.path.join(mount_point, reg_path.lstrip("/"))
        check_cmd = f"sudo test -f '{full_path}' && echo 'exists' || echo 'not_found'"
        stdout, stderr, exit_code = _execute_ssh_command(ssh_client, check_cmd)
        
        if "exists" in stdout:
            reg_name = os.path.basename(reg_path)
            artifacts["windows_artifacts"][f"registry_{reg_name.lower()}"] = {
                "path": reg_path,
                "extracted": False,
                "note": "Registry hive found but not extracted (binary file, requires specialized tools)"
            }
    
    return artifacts


def _get_forensic_instance_info(ec2_client, instance_id):
    """Get connection info for forensic instance."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if not response.get("Reservations"):
            return None, None, None
        
        instance = response["Reservations"][0]["Instances"][0]
        state = instance.get("State", {}).get("Name")
        
        if state != "running":
            return None, None, state
        
        public_ip = instance.get("PublicIpAddress")
        private_ip = instance.get("PrivateIpAddress")
        ip_address = public_ip or private_ip
        
        image_id = instance.get("ImageId", "").lower()
        if "ubuntu" in image_id or "debian" in image_id:
            default_user = "ubuntu"
        elif "amazon" in image_id or "amzn" in image_id:
            default_user = "ec2-user"
        elif "centos" in image_id or "rhel" in image_id:
            default_user = "centos"
        else:
            default_user = "ec2-user"
        
        return ip_address, default_user, state
        
    except Exception:
        return None, None, None


def _get_next_available_device(ssh_client, instance_id):
    """Find next available device name on forensic instance."""
    cmd = "lsblk -d -n -o NAME | grep -E '^[xv]d[b-z]$' | sort"
    stdout, stderr, exit_code = _execute_ssh_command(ssh_client, cmd)
    
    used_devices = set(stdout.strip().split("\n")) if stdout.strip() else set()
    
    for letter in "fghijklmnopqrstuvwxyz":
        for prefix in ["xvd", "sd"]:
            device = f"/dev/{prefix}{letter}"
            if device not in used_devices:
                check_cmd = f"test -b {device} && echo 'exists' || echo 'not_found'"
                stdout_check, _, _ = _execute_ssh_command(ssh_client, check_cmd)
                if "not_found" in stdout_check:
                    return device
    
    return "/dev/xvdf"


def extract_artifacts_from_snapshot_auto(ec2_client, snapshot_id, original_instance_id=None, case_dir=None):
    """
    Automatically extract forensic artifacts from a snapshot.
    Tries to use the original instance if available, otherwise skips with a warning.
    Returns dict with results.
    """
    result = {
        "snapshot_id": snapshot_id,
        "volume_id": None,
        "device": None,
        "mount_point": None,
        "filesystem_type": None,
        "artifacts": None,
        "errors": []
    }
    
    # Try to use original instance if provided and running
    forensic_instance_id = None
    if original_instance_id:
        try:
            response = ec2_client.describe_instances(InstanceIds=[original_instance_id])
            if response.get("Reservations"):
                instance = response["Reservations"][0]["Instances"][0]
                state = instance.get("State", {}).get("Name")
                if state == "running":
                    forensic_instance_id = original_instance_id
                    print(f"    Using original instance {original_instance_id} for artifact extraction")
        except Exception:
            pass
    
    if not forensic_instance_id:
        result["errors"].append("No running instance available for artifact extraction. Artifacts require a running instance to mount volumes.")
        return result
    
    # Get instance info and try to find SSH key automatically
    ip_address, default_user, state = _get_forensic_instance_info(ec2_client, forensic_instance_id)
    if not ip_address:
        result["errors"].append(f"Instance {forensic_instance_id} not accessible")
        return result
    
    # Try common SSH key locations
    common_key_paths = [
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.ssh/ventra_key.pem",
        "~/.ssh/ec2_key.pem",
    ]
    
    ssh_key_path = None
    for key_path in common_key_paths:
        expanded = os.path.expanduser(key_path)
        if os.path.exists(expanded):
            ssh_key_path = expanded
            break
    
    if not ssh_key_path:
        result["errors"].append("SSH key not found. Please ensure SSH key is available at ~/.ssh/id_rsa or configure SSH access.")
        return result
    
    # Use the existing extract function with auto-detected values
    return extract_artifacts_from_snapshot(
        ec2_client=ec2_client,
        snapshot_id=snapshot_id,
        forensic_instance_id=forensic_instance_id,
        ssh_key_path=ssh_key_path,
        ssh_user=None,  # Auto-detect
        ssh_port=22,
        case_dir=case_dir,
        instance_id=original_instance_id,
        cleanup=False  # Don't cleanup by default
    )


def extract_artifacts_from_snapshot(ec2_client, snapshot_id, forensic_instance_id, ssh_key_path, 
                                     ssh_user, ssh_port, case_dir, instance_id=None, cleanup=False):
    """
    Extract forensic artifacts from a snapshot.
    Creates volume, attaches to forensic instance, mounts, extracts, cleans up.
    Returns dict with results.
    """
    result = {
        "snapshot_id": snapshot_id,
        "volume_id": None,
        "device": None,
        "mount_point": None,
        "filesystem_type": None,
        "artifacts": None,
        "errors": []
    }
    
    # Get snapshot info
    try:
        snapshot_response = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
        if not snapshot_response.get("Snapshots"):
            result["errors"].append("Snapshot not found")
            return result
        
        snapshot_data = snapshot_response["Snapshots"][0]
        volume_size = snapshot_data.get("VolumeSize", 8)
        availability_zone = snapshot_data.get("AvailabilityZone")
    except Exception as e:
        result["errors"].append(f"Error describing snapshot: {e}")
        return result
    
    # Get forensic instance info
    ip_address, default_user, state = _get_forensic_instance_info(ec2_client, forensic_instance_id)
    if not ip_address:
        result["errors"].append(f"Forensic instance {forensic_instance_id} not running (state: {state})")
        return result
    
    username = ssh_user or default_user
    
    # Connect via SSH
    ssh_key_path_expanded = os.path.expanduser(ssh_key_path)
    ssh_key_path_abs = os.path.abspath(ssh_key_path_expanded)
    
    if not os.path.exists(ssh_key_path_abs):
        result["errors"].append(f"SSH key file not found: {ssh_key_path_abs}")
        return result
    
    ssh_client = None
    try:
        ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key_path_abs)
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname=ip_address,
            port=ssh_port,
            username=username,
            pkey=ssh_key,
            timeout=10,
        )
    except Exception as e:
        result["errors"].append(f"SSH connection failed: {e}")
        return result
    
    try:
        # Create volume from snapshot
        print(f"  [+] Creating volume from snapshot...")
        create_response = ec2_client.create_volume(
            SnapshotId=snapshot_id,
            AvailabilityZone=availability_zone,
            VolumeType="gp3",
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "VentraDFIR", "Value": "true"},
                        {"Key": "SnapshotId", "Value": snapshot_id},
                        {"Key": "CreatedBy", "Value": "Ventra"},
                    ]
                }
            ]
        )
        
        volume_id = create_response.get("VolumeId")
        result["volume_id"] = volume_id
        print(f"    ✓ Volume created: {volume_id}")
        
        if not _wait_for_volume_available(ec2_client, volume_id):
            result["errors"].append("Volume did not become available")
            return result
        
        # Attach volume
        print(f"  [+] Attaching volume to forensic instance...")
        device = _get_next_available_device(ssh_client, forensic_instance_id)
        
        ec2_client.attach_volume(
            VolumeId=volume_id,
            InstanceId=forensic_instance_id,
            Device=device
        )
        
        attached_device = _wait_for_attachment(ec2_client, volume_id, forensic_instance_id)
        if not attached_device:
            result["errors"].append("Volume attachment failed")
            return result
        
        result["device"] = attached_device
        print(f"    ✓ Volume attached as {attached_device}")
        time.sleep(3)
        
        # Mount volume
        print(f"  [+] Mounting volume read-only...")
        mount_point = f"/mnt/ventra_{snapshot_id.replace('-', '_')}"
        success, mount_info = _mount_volume_readonly(ssh_client, attached_device, mount_point)
        
        if not success:
            result["errors"].append(f"Mount failed: {mount_info}")
            return result
        
        result["mount_point"] = mount_point
        result["filesystem_type"] = _detect_filesystem_type(ssh_client, attached_device)
        print(f"    ✓ Volume mounted at {mount_point}")
        
        # Extract artifacts
        print(f"  [+] Extracting forensic artifacts...")
        fs_type = result["filesystem_type"]
        
        if fs_type in ["ext2", "ext3", "ext4", "xfs", "btrfs"]:
            artifacts = _extract_linux_artifacts(ssh_client, mount_point)
        elif fs_type in ["ntfs", "vfat"]:
            artifacts = _extract_windows_artifacts(ssh_client, mount_point)
        else:
            artifacts = _extract_linux_artifacts(ssh_client, mount_point)
            windows_artifacts = _extract_windows_artifacts(ssh_client, mount_point)
            artifacts["windows_artifacts"] = windows_artifacts.get("windows_artifacts", {})
            artifacts["artifacts_content"].update(windows_artifacts.get("artifacts_content", {}))
            artifacts["errors"].extend(windows_artifacts.get("errors", []))
        
        result["artifacts"] = artifacts
        artifact_count = len(artifacts.get("artifacts_content", {}))
        print(f"    ✓ Extracted {artifact_count} artifact(s)")
        
        # Unmount
        print(f"  [+] Unmounting volume...")
        _execute_ssh_command(ssh_client, f"sudo umount {mount_point}")
        
        # Detach
        print(f"  [+] Detaching volume...")
        ec2_client.detach_volume(VolumeId=volume_id)
        time.sleep(2)
        
        # Cleanup
        if cleanup:
            print(f"  [+] Deleting volume (cleanup mode)...")
            _wait_for_volume_available(ec2_client, volume_id, max_wait_minutes=2)
            ec2_client.delete_volume(VolumeId=volume_id)
            print(f"    ✓ Volume deleted")
    
    finally:
        if ssh_client:
            ssh_client.close()
    
    return result

