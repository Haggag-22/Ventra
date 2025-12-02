"""
API Gateway Integrations Collector
Collects integration configurations for API Gateway routes.
Critical for finding Lambda → API Gateway or S3 → API Gateway exfiltration endpoints.
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


def run_apigw_integrations(args):
    """Collect API Gateway integrations."""
    api_id = getattr(args, "api_id", None)
    
    print(f"[+] API Gateway Integrations Collector")
    if api_id:
        print(f"    API ID:      {api_id}")
    else:
        print(f"    All APIs:    Yes")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "resources")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        apigw_client = _get_apigw_client(args.region)
    except Exception as e:
        print(f"❌ Error getting API Gateway client: {e}")
        return
    
    try:
        integrations_data = {
            "apis_with_integrations": [],
        }
        
        # Get API IDs
        if api_id:
            api_ids = [api_id]
        else:
            print("[+] Listing all REST APIs...")
            response = apigw_client.get_rest_apis(limit=500)
            api_ids = [api.get("id") for api in response.get("items", [])]
            print(f"    ✓ Found {len(api_ids)} API(s)")
        
        # Get integrations for each API
        for api_id_item in api_ids:
            print(f"[+] Collecting integrations for API: {api_id_item}")
            
            try:
                api_integrations_info = {
                    "ApiId": api_id_item,
                    "Integrations": [],
                }
                
                # Get resources
                position = None
                while True:
                    kwargs = {"restApiId": api_id_item, "limit": 500}
                    if position:
                        kwargs["position"] = position
                    
                    resources_response = apigw_client.get_resources(**kwargs)
                    
                    for resource in resources_response.get("items", []):
                        resource_id = resource.get("id")
                        resource_methods = resource.get("resourceMethods", {})
                        
                        # Get integration for each method
                        for method in resource_methods.keys():
                            try:
                                integration_response = apigw_client.get_integration(
                                    restApiId=api_id_item,
                                    resourceId=resource_id,
                                    httpMethod=method
                                )
                                
                                integration_info = {
                                    "ApiId": api_id_item,
                                    "ResourceId": resource_id,
                                    "ResourcePath": resource.get("path"),
                                    "HttpMethod": method,
                                    "Type": integration_response.get("type"),
                                    "IntegrationHttpMethod": integration_response.get("httpMethod"),
                                    "Uri": integration_response.get("uri"),
                                    "ConnectionType": integration_response.get("connectionType"),
                                    "ConnectionId": integration_response.get("connectionId"),
                                    "Credentials": integration_response.get("credentials"),
                                    "RequestParameters": integration_response.get("requestParameters", {}),
                                    "RequestTemplates": integration_response.get("requestTemplates", {}),
                                    "PassthroughBehavior": integration_response.get("passthroughBehavior"),
                                    "ContentHandling": integration_response.get("contentHandling"),
                                    "TimeoutInMillis": integration_response.get("timeoutInMillis"),
                                    "CacheNamespace": integration_response.get("cacheNamespace"),
                                    "CacheKeyParameters": integration_response.get("cacheKeyParameters", []),
                                    "IntegrationResponses": integration_response.get("integrationResponses", {}),
                                }
                                
                                api_integrations_info["Integrations"].append(integration_info)
                                
                            except ClientError as e:
                                error_code = e.response.get("Error", {}).get("Code", "")
                                if error_code != "NotFoundException":
                                    print(f"      ⚠ Error getting integration for {method}: {e}")
                    
                    position = resources_response.get("position")
                    if not position:
                        break
                
                integrations_data["apis_with_integrations"].append(api_integrations_info)
                print(f"    ✓ Collected {len(api_integrations_info['Integrations'])} integration(s)")
                
            except ClientError as e:
                print(f"      ⚠ Error getting integrations: {e}")
        
        integrations_data["total_apis"] = len(integrations_data["apis_with_integrations"])
        
        # Save single combined file
        filename = "apigw_integrations.json"
        if api_id:
            filename = f"apigw_integrations_{api_id}.json"
        
        filepath = _save_json_file(output_dir, filename, integrations_data)
        if filepath:
            print(f"\n[✓] Saved integrations → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

