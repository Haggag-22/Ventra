"""
Lambda Policy Collector
Collects resource-based policy for a Lambda function.
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


def run_lambda_policy(args):
    """Collect Lambda function resource-based policy."""
    function_name = args.name
    print(f"[+] Lambda Policy Collector")
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
        policy_data = {}
        
        print("[+] Getting function policy...")
        try:
            response = lambda_client.get_policy(FunctionName=function_name)
            policy_data = {
                "FunctionName": function_name,
                "Policy": json.loads(response.get("Policy", "{}")),
                "RevisionId": response.get("RevisionId"),
            }
            print(f"    ✓ Collected policy")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                policy_data = {
                    "FunctionName": function_name,
                    "Policy": None,
                    "Message": "No resource-based policy configured",
                }
                print(f"    ⚠ No resource-based policy configured")
            else:
                print(f"    ❌ Error getting policy: {e}")
                return
        
        # Save single combined file
        safe_name = function_name.replace(":", "_").replace("/", "_")
        filename = f"lambda_policy_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, policy_data)
        if filepath:
            print(f"\n[✓] Saved policy → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

