"""
Lambda Environment Variables Collector
Collects environment variables for a Lambda function.
Often contains credentials or configuration used by attackers.
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


def run_lambda_env_vars(args):
    """Collect Lambda function environment variables."""
    function_name = args.name
    print(f"[+] Lambda Environment Variables Collector")
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
        env_vars_data = {}
        
        print("[+] Getting function configuration...")
        try:
            response = lambda_client.get_function_configuration(FunctionName=function_name)
            env_vars_data = {
                "FunctionName": function_name,
                "FunctionArn": response.get("FunctionArn"),
                "Environment": response.get("Environment", {}),
            }
            
            if env_vars_data["Environment"].get("Variables"):
                print(f"    ✓ Found {len(env_vars_data['Environment']['Variables'])} environment variable(s)")
            else:
                print(f"    ⚠ No environment variables configured")
        except ClientError as e:
            print(f"    ❌ Error getting configuration: {e}")
            return
        
        # Save single combined file
        safe_name = function_name.replace(":", "_").replace("/", "_")
        filename = f"lambda_env_vars_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, env_vars_data)
        if filepath:
            print(f"\n[✓] Saved environment variables → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

