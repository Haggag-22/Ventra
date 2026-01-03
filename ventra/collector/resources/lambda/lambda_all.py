"""
Lambda All Collector
Collects all Lambda function information (config, env vars, policy, code metadata) into a single combined file.
"""
import os
import json
import boto3
import zipfile
import io
import urllib.request
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_lambda_client(region):
    """Lambda client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("lambda")


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


def _resolve_function_name(lambda_client, function_identifier):
    """
    Resolve function identifier (name or ARN) to function name.
    Returns function name if found, None otherwise.
    """
    # If it's already a valid function name, try it first
    try:
        lambda_client.get_function_configuration(FunctionName=function_identifier)
        return function_identifier
    except ClientError:
        pass
    
    # Try to extract function name from ARN
    if function_identifier.startswith("arn:aws:lambda:"):
        # Extract function name from ARN format: arn:aws:lambda:region:account:function:function-name
        parts = function_identifier.split(":")
        if len(parts) >= 7:
            func_name = parts[6]
            # Handle version/alias suffixes
            if ":" in func_name:
                func_name = func_name.split(":")[0]
            try:
                lambda_client.get_function_configuration(FunctionName=func_name)
                return func_name
            except ClientError:
                pass
    
    # Try listing all functions and finding a match
    try:
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                func_name = func.get("FunctionName")
                func_arn = func.get("FunctionArn")
                if func_name == function_identifier or func_arn == function_identifier:
                    return func_name
                # Try partial match
                if func_name and function_identifier in func_name:
                    return func_name
    except ClientError:
        pass
    
    return None


def _collect_function_config(lambda_client, function_name):
    """Collect function configuration."""
    config = {}
    try:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        config = {
            "FunctionName": response.get("FunctionName"),
            "FunctionArn": response.get("FunctionArn"),
            "Runtime": response.get("Runtime"),
            "Role": response.get("Role"),
            "Handler": response.get("Handler"),
            "CodeSize": response.get("CodeSize"),
            "Description": response.get("Description"),
            "Timeout": response.get("Timeout"),
            "MemorySize": response.get("MemorySize"),
            "LastModified": str(response.get("LastModified", "")),
            "CodeSha256": response.get("CodeSha256"),
            "Version": response.get("Version"),
            "VpcConfig": response.get("VpcConfig"),
            "DeadLetterConfig": response.get("DeadLetterConfig"),
            "Environment": response.get("Environment"),
            "KMSKeyArn": response.get("KMSKeyArn"),
            "TracingConfig": response.get("TracingConfig"),
            "MasterArn": response.get("MasterArn"),
            "RevisionId": response.get("RevisionId"),
            "Layers": response.get("Layers", []),
            "State": response.get("State"),
            "StateReason": response.get("StateReason"),
            "StateReasonCode": response.get("StateReasonCode"),
            "LastUpdateStatus": response.get("LastUpdateStatus"),
            "LastUpdateStatusReason": response.get("LastUpdateStatusReason"),
            "LastUpdateStatusReasonCode": response.get("LastUpdateStatusReasonCode"),
            "PackageType": response.get("PackageType"),
            "Architectures": response.get("Architectures", []),
            "EphemeralStorage": response.get("EphemeralStorage"),
            "SnapStart": response.get("SnapStart"),
            "RuntimeVersionConfig": response.get("RuntimeVersionConfig"),
        }
    except ClientError as e:
        print(f"      ⚠ Error getting function configuration: {e}")
    except Exception as e:
        print(f"      ⚠ Error getting function configuration: {e}")
    
    return config


def _collect_function_url(lambda_client, function_name):
    """Collect function URL configuration."""
    url_config = None
    try:
        response = lambda_client.get_function_url_config(FunctionName=function_name)
        url_config = response
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "ResourceNotFoundException":
            print(f"      ⚠ Error getting function URL: {e}")
    except Exception as e:
        print(f"      ⚠ Error getting function URL: {e}")
    
    return url_config


def _collect_concurrency_config(lambda_client, function_name):
    """Collect concurrency configuration."""
    concurrency = None
    try:
        response = lambda_client.get_function_concurrency(FunctionName=function_name)
        concurrency = response.get("ReservedConcurrentExecutions")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "ResourceNotFoundException":
            print(f"      ⚠ Error getting concurrency config: {e}")
    except Exception as e:
        print(f"      ⚠ Error getting concurrency config: {e}")
    
    return concurrency


def _collect_function_policy(lambda_client, function_name):
    """Collect resource-based policy."""
    policy = None
    try:
        response = lambda_client.get_policy(FunctionName=function_name)
        policy = {
            "Policy": json.loads(response.get("Policy", "{}")),
            "RevisionId": response.get("RevisionId"),
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "ResourceNotFoundException":
            print(f"      ⚠ Error getting function policy: {e}")
    except Exception as e:
        print(f"      ⚠ Error getting function policy: {e}")
    
    return policy


def _extract_zip_info(zip_data):
    """Extract file list and basic info from ZIP."""
    try:
        zip_file = zipfile.ZipFile(io.BytesIO(zip_data))
        files = []
        for info in zip_file.infolist():
            files.append({
                "filename": info.filename,
                "file_size": info.file_size,
                "compress_size": info.compress_size,
                "date_time": str(info.date_time),
                "is_dir": info.is_dir(),
            })
        return files
    except Exception as e:
        return None


def _collect_function_code(lambda_client, function_name, output_dir):
    """Collect function code metadata and download if possible."""
    code_data = {
        "CodeLocation": None,
        "RepositoryType": None,
        "Downloaded": False,
        "ZipFile": None,
        "ZipSize": None,
        "ZipContents": None,
    }
    
    try:
        response = lambda_client.get_function(FunctionName=function_name)
        code_location = response.get("Code", {}).get("Location")
        code_repository_type = response.get("Code", {}).get("RepositoryType")
        
        code_data["CodeLocation"] = code_location
        code_data["RepositoryType"] = code_repository_type
        code_data["CodeSize"] = response.get("Configuration", {}).get("CodeSize")
        code_data["CodeSha256"] = response.get("Configuration", {}).get("CodeSha256")
        
        # Download the code if it's available via URL (not container image)
        if code_repository_type == "S3":
            code_data["Message"] = "Code stored in S3, use S3 collector to download"
        elif code_location and code_repository_type != "ECR":
            # Try to download via get_function URL
            try:
                with urllib.request.urlopen(code_location) as response_url:
                    zip_data = response_url.read()
                    
                    # Save ZIP file
                    safe_name = function_name.replace(":", "_").replace("/", "_")
                    zip_filename = f"lambda_code_{safe_name}.zip"
                    zip_filepath = os.path.join(output_dir, zip_filename)
                    with open(zip_filepath, "wb") as f:
                        f.write(zip_data)
                    
                    code_data["Downloaded"] = True
                    code_data["ZipFile"] = zip_filename
                    code_data["ZipSize"] = len(zip_data)
                    
                    # Extract ZIP contents info
                    zip_info = _extract_zip_info(zip_data)
                    code_data["ZipContents"] = zip_info
                    
            except Exception as e:
                print(f"      ⚠ Error downloading code: {e}")
                code_data["Error"] = str(e)
                
    except ClientError as e:
        print(f"      ⚠ Error getting function code: {e}")
    except Exception as e:
        print(f"      ⚠ Error getting function code: {e}")
    
    return code_data


def run_lambda_all(args):
    """Collect all Lambda function data into a single file."""
    function_identifier = getattr(args, "name", None)
    
    if not function_identifier:
        print("❌ Error: --name parameter is required")
        print("   Usage: ventra collect lambda all --case <case> --name <function_name_or_arn>")
        return
    
    print(f"[+] Lambda All Collector")
    print(f"    Function:    {function_identifier}")
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
        lambda_client = _get_lambda_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Lambda client: {e}")
        return
    
    try:
        # Resolve function name
        print(f"[+] Resolving function identifier...")
        function_name = _resolve_function_name(lambda_client, function_identifier)
        if not function_name:
            print(f"❌ Error: Could not find function with identifier: {function_identifier}")
            return
        
        print(f"    ✓ Found function: {function_name}\n")
        
        # Collect all data
        all_data = {
            "FunctionName": function_name,
            "Config": {},
            "FunctionUrl": None,
            "Concurrency": None,
            "Policy": None,
            "Code": {},
        }
        
        # Collect configuration
        print(f"[+] Collecting function configuration...")
        try:
            all_data["Config"] = _collect_function_config(lambda_client, function_name)
            print(f"    ✓ Collected configuration")
        except Exception as e:
            print(f"    ⚠ Error collecting configuration: {e} (continuing)")
        
        # Collect function URL
        print(f"[+] Collecting function URL configuration...")
        try:
            all_data["FunctionUrl"] = _collect_function_url(lambda_client, function_name)
            if all_data["FunctionUrl"]:
                print(f"    ✓ Function URL configured")
            else:
                print(f"    ⚠ No function URL configured")
        except Exception as e:
            print(f"    ⚠ Error collecting function URL: {e} (continuing)")
        
        # Collect concurrency
        print(f"[+] Collecting concurrency configuration...")
        try:
            all_data["Concurrency"] = _collect_concurrency_config(lambda_client, function_name)
            if all_data["Concurrency"]:
                print(f"    ✓ Concurrency: {all_data['Concurrency']}")
            else:
                print(f"    ⚠ No reserved concurrency set")
        except Exception as e:
            print(f"    ⚠ Error collecting concurrency: {e} (continuing)")
        
        # Collect policy
        print(f"[+] Collecting resource-based policy...")
        try:
            all_data["Policy"] = _collect_function_policy(lambda_client, function_name)
            if all_data["Policy"]:
                print(f"    ✓ Collected policy")
            else:
                print(f"    ⚠ No resource-based policy configured")
        except Exception as e:
            print(f"    ⚠ Error collecting policy: {e} (continuing)")
        
        # Collect code
        print(f"[+] Collecting function code...")
        try:
            all_data["Code"] = _collect_function_code(lambda_client, function_name, output_dir)
            if all_data["Code"].get("Downloaded"):
                print(f"    ✓ Downloaded code ZIP ({all_data['Code'].get('ZipSize', 0)} bytes)")
                if all_data["Code"].get("ZipContents"):
                    print(f"    ✓ ZIP contains {len(all_data['Code']['ZipContents'])} file(s)")
            else:
                print(f"    ⚠ Code metadata collected (code not downloaded)")
        except Exception as e:
            print(f"    ⚠ Error collecting code: {e} (continuing)")
        
        # Get function ID for filename - sanitize function name
        safe_name = function_name.replace(":", "_").replace("/", "_").replace(" ", "_")
        filename = f"lambda_{safe_name}_all.json"
        
        # Save combined file
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all Lambda data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

