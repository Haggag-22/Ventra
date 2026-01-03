"""
Lambda Config Collector
Collects detailed configuration for a specific Lambda function.
"""
import os
import json
import boto3
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


def run_lambda_config(args):
    """Collect Lambda function configuration."""
    function_name = args.name
    print(f"[+] Lambda Config Collector")
    print(f"    Function:    {function_name}")
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
        config_data = {}
        
        print("[+] Getting function configuration...")
        try:
            response = lambda_client.get_function_configuration(FunctionName=function_name)
            config_data = {
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
            print(f"    ✓ Collected configuration")
        except ClientError as e:
            print(f"    ❌ Error getting configuration: {e}")
            return
        
        # Get function URL config if exists
        print("[+] Checking for function URL...")
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=function_name)
            config_data["FunctionUrlConfig"] = url_config
            print(f"    ✓ Function URL configured")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                config_data["FunctionUrlConfig"] = None
                print(f"    ⚠ No function URL configured")
            else:
                print(f"    ⚠ Error getting function URL: {e}")
        
        # Get concurrency config
        print("[+] Getting concurrency configuration...")
        try:
            concurrency = lambda_client.get_function_concurrency(FunctionName=function_name)
            config_data["ReservedConcurrentExecutions"] = concurrency.get("ReservedConcurrentExecutions")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                config_data["ReservedConcurrentExecutions"] = None
            else:
                print(f"    ⚠ Error getting concurrency: {e}")
        
        # Save single combined file
        safe_name = function_name.replace(":", "_").replace("/", "_")
        filename = f"lambda_config_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, config_data)
        if filepath:
            print(f"\n[✓] Saved configuration → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

