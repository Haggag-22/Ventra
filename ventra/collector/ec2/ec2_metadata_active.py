import os
import json
import paramiko
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


def _check_instance_state(ec2_client, instance_id):
    """
    Check if instance is running. Returns (is_running, instance_data).
    """
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response.get("Reservations"):
            return False, None
        
        instance_data = response["Reservations"][0]["Instances"][0]
        state = instance_data.get("State", {}).get("Name", "")
        
        return state == "running", instance_data
    except ClientError as e:
        return False, None


def _get_instance_connection_info(instance_data):
    """
    Extract connection info (IP, username) from instance data.
    """
    # Try public IP first, fallback to private IP
    public_ip = instance_data.get("PublicIpAddress")
    private_ip = instance_data.get("PrivateIpAddress")
    ip_address = public_ip or private_ip
    
    if not ip_address:
        return None, None
    
    # Determine username based on AMI (common defaults)
    # User can override with --ssh-user
    image_id = instance_data.get("ImageId", "").lower()
    if "ubuntu" in image_id or "debian" in image_id:
        default_user = "ubuntu"
    elif "amazon" in image_id or "amzn" in image_id:
        default_user = "ec2-user"
    elif "centos" in image_id or "rhel" in image_id:
        default_user = "centos"
    else:
        default_user = "ec2-user"  # Default fallback
    
    return ip_address, default_user


def _execute_ssh_command(ssh_client, command):
    """
    Execute a command via SSH and return stdout, stderr, and exit code.
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    stdout_text = stdout.read().decode("utf-8")
    stderr_text = stderr.read().decode("utf-8")
    return stdout_text, stderr_text, exit_code


def _get_imdsv2_token(ssh_client):
    """
    Get IMDSv2 token via SSH.
    """
    command = 'curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"'
    stdout, stderr, exit_code = _execute_ssh_command(ssh_client, command)
    
    if exit_code == 0 and stdout.strip():
        return stdout.strip()
    return None


def _query_imds_endpoint(ssh_client, token, endpoint):
    """
    Query an IMDS endpoint using IMDSv2 token.
    Returns the response text or None.
    """
    if token:
        command = f'curl -s -H "X-aws-ec2-metadata-token: {token}" "http://169.254.169.254{endpoint}"'
    else:
        # Fallback to IMDSv1
        command = f'curl -s "http://169.254.169.254{endpoint}"'
    
    stdout, stderr, exit_code = _execute_ssh_command(ssh_client, command)
    
    if exit_code == 0:
        return stdout.strip()
    return None


def _list_imds_paths(ssh_client, token, base_path="/latest/meta-data/"):
    """
    List all available paths under an IMDS endpoint.
    """
    result = _query_imds_endpoint(ssh_client, token, base_path)
    if result:
        return [line.strip() for line in result.split("\n") if line.strip()]
    return []


def _collect_imds_metadata(ssh_client, token):
    """
    Collect all IMDS metadata according to the comprehensive list.
    """
    metadata = {}
    
    # ===================================================================
    # 1. IDENTITY: instance-id, ami-id, instance-type
    # ===================================================================
    print("    [+] Collecting identity metadata...")
    identity = {}
    identity["instance-id"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/instance-id")
    identity["ami-id"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/ami-id")
    identity["instance-type"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/instance-type")
    metadata["identity"] = identity
    
    # ===================================================================
    # 2. NETWORKING: macs/, vpc, subnet, SGs
    # ===================================================================
    print("    [+] Collecting networking metadata...")
    networking = {}
    
    # Get MAC addresses
    macs = _list_imds_paths(ssh_client, token, "/latest/meta-data/network/interfaces/macs/")
    networking["macs"] = macs
    
    # Collect details for each network interface
    network_interfaces = {}
    for ni_mac in macs:
        ni_data = {}
        ni_base = f"/latest/meta-data/network/interfaces/macs/{ni_mac}"
        
        # VPC, Subnet, Security Groups
        ni_data["vpc-id"] = _query_imds_endpoint(ssh_client, token, f"{ni_base}/vpc-id")
        ni_data["subnet-id"] = _query_imds_endpoint(ssh_client, token, f"{ni_base}/subnet-id")
        ni_data["subnet-ipv4-cidr-block"] = _query_imds_endpoint(ssh_client, token, f"{ni_base}/subnet-ipv4-cidr-block")
        ni_data["vpc-ipv4-cidr-block"] = _query_imds_endpoint(ssh_client, token, f"{ni_base}/vpc-ipv4-cidr-block")
        
        # Security Groups
        sg_ids = _list_imds_paths(ssh_client, token, f"{ni_base}/security-group-ids/")
        sg_names = _list_imds_paths(ssh_client, token, f"{ni_base}/security-groups/")
        ni_data["security-group-ids"] = sg_ids
        ni_data["security-groups"] = sg_names
        
        # Additional network interface properties
        ni_properties = [
            "device-number",
            "interface-id",
            "local-hostname",
            "local-ipv4s",
            "mac",
            "owner-id",
            "public-hostname",
            "public-ipv4s",
        ]
        
        for prop in ni_properties:
            value = _query_imds_endpoint(ssh_client, token, f"{ni_base}/{prop}")
            if value:
                ni_data[prop] = value
        
        network_interfaces[ni_mac] = ni_data
    
    networking["interfaces"] = network_interfaces
    
    # Also get top-level networking info
    networking["public-ipv4"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/public-ipv4")
    networking["local-ipv4"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/local-ipv4")
    networking["public-hostname"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/public-hostname")
    networking["local-hostname"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/local-hostname")
    networking["mac"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/mac")
    
    metadata["networking"] = networking
    
    # ===================================================================
    # 3. IAM CREDENTIALS: iam/security-credentials/*
    # ===================================================================
    print("    [+] Collecting IAM credentials...")
    iam_paths = _list_imds_paths(ssh_client, token, "/latest/meta-data/iam/security-credentials/")
    if iam_paths:
        iam_credentials = {}
        for role_name in iam_paths:
            creds_json = _query_imds_endpoint(ssh_client, token, f"/latest/meta-data/iam/security-credentials/{role_name}")
            if creds_json:
                try:
                    iam_credentials[role_name] = json.loads(creds_json)
                except json.JSONDecodeError:
                    iam_credentials[role_name] = creds_json
        
        if iam_credentials:
            metadata["iam_security_credentials"] = iam_credentials
    
    # ===================================================================
    # 4. STORAGE: block-device-mapping/, ebs/
    # ===================================================================
    print("    [+] Collecting storage metadata...")
    storage = {}
    
    # Block device mapping
    bdm_paths = _list_imds_paths(ssh_client, token, "/latest/meta-data/block-device-mapping/")
    block_devices = {}
    for device in bdm_paths:
        value = _query_imds_endpoint(ssh_client, token, f"/latest/meta-data/block-device-mapping/{device}")
        if value:
            block_devices[device] = value
    
    if block_devices:
        storage["block_device_mapping"] = block_devices
    
    # EBS volumes
    ebs_paths = _list_imds_paths(ssh_client, token, "/latest/meta-data/block-device-mapping/ebs/")
    if ebs_paths:
        ebs_devices = {}
        for device in ebs_paths:
            value = _query_imds_endpoint(ssh_client, token, f"/latest/meta-data/block-device-mapping/ebs/{device}")
            if value:
                ebs_devices[device] = value
        if ebs_devices:
            storage["ebs"] = ebs_devices
    
    # Also try direct ebs/ path
    ebs_direct = _list_imds_paths(ssh_client, token, "/latest/meta-data/ebs/")
    if ebs_direct:
        ebs_info = {}
        for item in ebs_direct:
            value = _query_imds_endpoint(ssh_client, token, f"/latest/meta-data/ebs/{item}")
            if value:
                ebs_info[item] = value
        if ebs_info:
            storage["ebs_direct"] = ebs_info
    
    if storage:
        metadata["storage"] = storage
    
    # ===================================================================
    # 5. PLACEMENT: region, availability-zone
    # ===================================================================
    print("    [+] Collecting placement metadata...")
    placement = {}
    placement["region"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/placement/region")
    placement["availability-zone"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/placement/availability-zone")
    placement["availability-zone-id"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/placement/availability-zone-id")
    metadata["placement"] = placement
    
    # ===================================================================
    # 6. TAGS: tags/instance/*
    # ===================================================================
    print("    [+] Collecting tags...")
    tag_paths = _list_imds_paths(ssh_client, token, "/latest/meta-data/tags/instance/")
    if tag_paths:
        tags = {}
        for tag_key in tag_paths:
            tag_value = _query_imds_endpoint(ssh_client, token, f"/latest/meta-data/tags/instance/{tag_key}")
            if tag_value:
                tags[tag_key] = tag_value
        
        if tags:
            metadata["tags"] = tags
    
    # ===================================================================
    # 7. LIFECYCLE: instance-life-cycle
    # ===================================================================
    print("    [+] Collecting lifecycle metadata...")
    lifecycle = {}
    lifecycle["instance-life-cycle"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/instance-life-cycle")
    lifecycle["spot"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/spot/instance-action")
    metadata["lifecycle"] = lifecycle
    
    # ===================================================================
    # 8. USER DATA: user-data
    # ===================================================================
    print("    [+] Collecting user data...")
    user_data = _query_imds_endpoint(ssh_client, token, "/latest/user-data")
    if user_data:
        metadata["user_data"] = user_data
    
    # ===================================================================
    # 9. DYNAMIC IDENTITY: dynamic/instance-identity/document
    # ===================================================================
    print("    [+] Collecting dynamic identity document...")
    identity_doc_json = _query_imds_endpoint(ssh_client, token, "/latest/dynamic/instance-identity/document")
    if identity_doc_json:
        try:
            metadata["dynamic_instance_identity_document"] = json.loads(identity_doc_json)
        except json.JSONDecodeError:
            metadata["dynamic_instance_identity_document"] = identity_doc_json
    
    # Also get signature and PKCS7
    identity_pkcs7 = _query_imds_endpoint(ssh_client, token, "/latest/dynamic/instance-identity/pkcs7")
    if identity_pkcs7:
        metadata["dynamic_instance_identity_pkcs7"] = identity_pkcs7
    
    identity_signature = _query_imds_endpoint(ssh_client, token, "/latest/dynamic/instance-identity/signature")
    if identity_signature:
        metadata["dynamic_instance_identity_signature"] = identity_signature
    
    # ===================================================================
    # 10. CREDENTIALS: dynamic/credentials/*
    # ===================================================================
    print("    [+] Collecting dynamic credentials...")
    creds_paths = _list_imds_paths(ssh_client, token, "/latest/dynamic/credentials/")
    if creds_paths:
        dynamic_credentials = {}
        for cred_item in creds_paths:
            value = _query_imds_endpoint(ssh_client, token, f"/latest/dynamic/credentials/{cred_item}")
            if value:
                try:
                    dynamic_credentials[cred_item] = json.loads(value)
                except json.JSONDecodeError:
                    dynamic_credentials[cred_item] = value
        
        if dynamic_credentials:
            metadata["dynamic_credentials"] = dynamic_credentials
    
    # ===================================================================
    # Additional metadata for completeness
    # ===================================================================
    print("    [+] Collecting additional metadata...")
    additional = {}
    additional["hostname"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/hostname")
    additional["local-hostname"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/local-hostname")
    additional["public-hostname"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/public-hostname")
    additional["kernel-id"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/kernel-id")
    additional["ramdisk-id"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/ramdisk-id")
    additional["reservation-id"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/reservation-id")
    additional["security-groups"] = _query_imds_endpoint(ssh_client, token, "/latest/meta-data/security-groups")
    metadata["additional"] = additional
    
    return metadata


def _collect_instance_metadata(ec2_client, instance_id, ssh_key_path, ssh_user, ssh_port=22):
    """
    Collect internal metadata from a running EC2 instance via SSH + IMDS.
    """
    result = {
        "instance_id": instance_id,
        "collection_method": "SSH + IMDSv2",
        "metadata": None,
        "error": None,
    }
    
    # Check instance state
    is_running, instance_data = _check_instance_state(ec2_client, instance_id)
    if not is_running:
        result["error"] = "Instance is not running. Internal metadata collection requires a running instance."
        return result
    
    # Get connection info
    ip_address, default_user = _get_instance_connection_info(instance_data)
    if not ip_address:
        result["error"] = "Could not determine IP address for instance."
        return result
    
    # Use provided user or default
    username = ssh_user or default_user
    
    # Connect via SSH
    ssh_client = None
    try:
        print(f"  [+] Connecting to {username}@{ip_address}:{ssh_port}...")
        
        # Expand and validate SSH key path
        ssh_key_path_expanded = os.path.expanduser(ssh_key_path)
        ssh_key_path_abs = os.path.abspath(ssh_key_path_expanded)
        
        if not os.path.exists(ssh_key_path_abs):
            result["error"] = f"SSH key file not found: {ssh_key_path_abs}"
            return result
        
        # Load SSH key
        ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key_path_abs)
        
        # Create SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname=ip_address,
            port=ssh_port,
            username=username,
            pkey=ssh_key,
            timeout=10,
        )
        
        print(f"    ✓ SSH connection established")
        
        # Get IMDSv2 token
        print(f"  [+] Requesting IMDSv2 token...")
        token = _get_imdsv2_token(ssh_client)
        
        if token:
            print(f"    ✓ IMDSv2 token obtained")
        else:
            print(f"    ⚠ IMDSv2 not available, falling back to IMDSv1")
        
        # Collect IMDS metadata
        print(f"  [+] Collecting IMDS metadata...")
        metadata = _collect_imds_metadata(ssh_client, token)
        
        result["metadata"] = metadata
        print(f"    ✓ Collected internal metadata")
        
    except FileNotFoundError:
        result["error"] = f"SSH key file not found: {ssh_key_path}"
    except paramiko.AuthenticationException:
        result["error"] = f"SSH authentication failed. Check username ({username}) and key file."
    except paramiko.SSHException as e:
        result["error"] = f"SSH connection error: {e}"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
    finally:
        if ssh_client:
            ssh_client.close()
    
    return result


def run_ec2_metadata_active(args):
    """
    Collect EC2 internal metadata via SSH + IMDS for one or more instances.
    WARNING: This requires SSH access and a running instance.
    """
    print("[+] EC2 Active Metadata Collector (SSH + IMDS)")
    print("    ⚠ WARNING: This collector connects to running instances via SSH.")
    print("    ⚠ This may modify evidence and should only be used for live response.")
    print(f"    Instances:  {', '.join(args.instance)}")
    print(f"    Region:     {args.region}")
    print(f"    SSH Key:    {args.ssh_key}")
    if args.ssh_user:
        print(f"    SSH User:   {args.ssh_user}")
    print()
    
    # Get output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    else:
        output_dir = args.output or "/Users/omar/Desktop/Ventra/output"
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"    Output:     {output_dir}\n")
    
    # Get AWS clients
    try:
        ec2_client = _get_ec2_client(args.region)
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
        
        result = _collect_instance_metadata(
            ec2_client,
            instance_id,
            args.ssh_key,
            args.ssh_user,
            args.ssh_port if hasattr(args, "ssh_port") else 22,
        )
        
        if result.get("metadata") and not result.get("error"):
            all_results.append(result)
            successful_instances.append(instance_id)
        else:
            failed_instances.append(instance_id)
            if result.get("error"):
                print(f"  ❌ {result['error']}")
        
        print("=" * 60)
    
    # Create combined summary file
    if all_results:
        summary_data = {
            "collection_timestamp": datetime.utcnow().isoformat() + "Z",
            "collection_method": "SSH + IMDSv2",
            "warning": "This data was collected from running instances via SSH. Use with caution in forensic investigations.",
            "total_instances": len(args.instance),
            "successful": len(successful_instances),
            "failed": len(failed_instances),
            "successful_instance_ids": successful_instances,
            "failed_instance_ids": failed_instances,
            "instances": all_results,
        }
        
        # Use case_dir if available, otherwise output_dir
        final_output_dir = args.case_dir if hasattr(args, "case_dir") and args.case_dir else output_dir
        summary_path = os.path.join(final_output_dir, "ec2_active_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, default=str)
        
        print(f"\n[✓] Collection complete")
        print(f"    Successful: {len(successful_instances)} instance(s)")
        if failed_instances:
            print(f"    Failed: {len(failed_instances)} instance(s): {', '.join(failed_instances)}")
        print(f"    Summary saved: {summary_path}\n")
    else:
        print(f"\n❌ No instances were successfully collected.\n")

