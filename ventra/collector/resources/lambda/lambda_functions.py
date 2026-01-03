"""
Lambda Functions Collector
Collects list of all Lambda functions.
Attackers love Lambda for persistence: no EC2 logs, hidden execution, no SSH/RDP required.
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


def run_lambda_functions(args):
    """Collect all Lambda functions."""
    print(f"[+] Lambda Functions Collector")
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
        functions_data = {
            "functions": [],
        }
        
        print("[+] Listing all Lambda functions...")
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                func_info = {
                    "FunctionName": func.get("FunctionName"),
                    "FunctionArn": func.get("FunctionArn"),
                    "Runtime": func.get("Runtime"),
                    "Role": func.get("Role"),
                    "Handler": func.get("Handler"),
                    "CodeSize": func.get("CodeSize"),
                    "Description": func.get("Description"),
                    "Timeout": func.get("Timeout"),
                    "MemorySize": func.get("MemorySize"),
                    "LastModified": str(func.get("LastModified", "")),
                    "CodeSha256": func.get("CodeSha256"),
                    "Version": func.get("Version"),
                    "VpcConfig": func.get("VpcConfig"),
                    "DeadLetterConfig": func.get("DeadLetterConfig"),
                    "Environment": func.get("Environment"),
                    "KMSKeyArn": func.get("KMSKeyArn"),
                    "TracingConfig": func.get("TracingConfig"),
                    "MasterArn": func.get("MasterArn"),
                    "RevisionId": func.get("RevisionId"),
                    "Layers": func.get("Layers", []),
                    "State": func.get("State"),
                    "StateReason": func.get("StateReason"),
                    "StateReasonCode": func.get("StateReasonCode"),
                    "LastUpdateStatus": func.get("LastUpdateStatus"),
                    "LastUpdateStatusReason": func.get("LastUpdateStatusReason"),
                    "LastUpdateStatusReasonCode": func.get("LastUpdateStatusReasonCode"),
                    "PackageType": func.get("PackageType"),
                    "Architectures": func.get("Architectures", []),
                }
                functions_data["functions"].append(func_info)
        
        functions_data["total_functions"] = len(functions_data["functions"])
        print(f"    ✓ Found {functions_data['total_functions']} function(s)")
        
        # Save single combined file
        filename = "lambda_functions.json"
        filepath = _save_json_file(output_dir, filename, functions_data)
        if filepath:
            print(f"\n[✓] Saved functions → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

