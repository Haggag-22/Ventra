"""
API Gateway REST APIs Collector
Collects API Gateway REST APIs.
Attackers create API Gateway → Lambda → persistence or API Gateway → S3 exfiltration endpoints.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_apigw_client(region):
    """API Gateway client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("apigateway")


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


def run_apigw_rest_apis(args):
    """Collect API Gateway REST APIs."""
    print(f"[+] API Gateway REST APIs Collector")
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
        apigw_client = _get_apigw_client(args.region)
    except Exception as e:
        print(f"❌ Error getting API Gateway client: {e}")
        return
    
    try:
        apis_data = {
            "rest_apis": [],
        }
        
        print("[+] Listing all REST APIs...")
        position = None
        while True:
            kwargs = {"limit": 500}
            if position:
                kwargs["position"] = position
            
            response = apigw_client.get_rest_apis(**kwargs)
            
            for api in response.get("items", []):
                api_id = api.get("id")
                
                api_info = {
                    "Id": api_id,
                    "Name": api.get("name"),
                    "Description": api.get("description"),
                    "CreatedDate": str(api.get("createdDate", "")),
                    "Version": api.get("version"),
                    "Warnings": api.get("warnings", []),
                    "BinaryMediaTypes": api.get("binaryMediaTypes", []),
                    "MinimumCompressionSize": api.get("minimumCompressionSize"),
                    "ApiKeySource": api.get("apiKeySource"),
                    "EndpointConfiguration": api.get("endpointConfiguration", {}),
                    "Policy": api.get("policy"),
                    "Tags": api.get("tags", {}),
                }
                
                apis_data["rest_apis"].append(api_info)
            
            position = response.get("position")
            if not position:
                break
        
        apis_data["total_apis"] = len(apis_data["rest_apis"])
        print(f"    ✓ Found {apis_data['total_apis']} REST API(s)")
        
        # Save single combined file
        filename = "apigw_rest_apis.json"
        filepath = _save_json_file(output_dir, filename, apis_data)
        if filepath:
            print(f"\n[✓] Saved REST APIs → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

