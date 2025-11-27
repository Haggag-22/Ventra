"""
API Gateway Routes Collector
Collects routes (resources and methods) for REST APIs.
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


def run_apigw_routes(args):
    """Collect API Gateway routes."""
    api_id = getattr(args, "api_id", None)
    
    print(f"[+] API Gateway Routes Collector")
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
    
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        apigw_client = _get_apigw_client(args.region)
    except Exception as e:
        print(f"❌ Error getting API Gateway client: {e}")
        return
    
    try:
        routes_data = {
            "apis_with_routes": [],
        }
        
        # Get API IDs
        if api_id:
            api_ids = [api_id]
        else:
            print("[+] Listing all REST APIs...")
            response = apigw_client.get_rest_apis(limit=500)
            api_ids = [api.get("id") for api in response.get("items", [])]
            print(f"    ✓ Found {len(api_ids)} API(s)")
        
        # Get routes for each API
        for api_id_item in api_ids:
            print(f"[+] Collecting routes for API: {api_id_item}")
            
            try:
                api_routes_info = {
                    "ApiId": api_id_item,
                    "Resources": [],
                }
                
                # Get resources (routes)
                position = None
                while True:
                    kwargs = {"restApiId": api_id_item, "limit": 500}
                    if position:
                        kwargs["position"] = position
                    
                    resources_response = apigw_client.get_resources(**kwargs)
                    
                    for resource in resources_response.get("items", []):
                        resource_id = resource.get("id")
                        
                        resource_info = {
                            "Id": resource_id,
                            "Path": resource.get("path"),
                            "PathPart": resource.get("pathPart"),
                            "ParentId": resource.get("parentId"),
                            "ResourceMethods": resource.get("resourceMethods", {}),
                        }
                        
                        # Get method details for each HTTP method
                        for method in resource_info["ResourceMethods"].keys():
                            try:
                                method_response = apigw_client.get_method(
                                    restApiId=api_id_item,
                                    resourceId=resource_id,
                                    httpMethod=method
                                )
                                resource_info["ResourceMethods"][method] = {
                                    "HttpMethod": method_response.get("httpMethod"),
                                    "AuthorizationType": method_response.get("authorizationType"),
                                    "AuthorizerId": method_response.get("authorizerId"),
                                    "ApiKeyRequired": method_response.get("apiKeyRequired"),
                                    "RequestValidatorId": method_response.get("requestValidatorId"),
                                    "OperationName": method_response.get("operationName"),
                                    "RequestParameters": method_response.get("requestParameters", {}),
                                    "RequestModels": method_response.get("requestModels", {}),
                                    "MethodResponses": method_response.get("methodResponses", {}),
                                }
                            except ClientError:
                                pass
                        
                        api_routes_info["Resources"].append(resource_info)
                    
                    position = resources_response.get("position")
                    if not position:
                        break
                
                routes_data["apis_with_routes"].append(api_routes_info)
                print(f"    ✓ Collected {len(api_routes_info['Resources'])} resource(s)")
                
            except ClientError as e:
                print(f"      ⚠ Error getting routes: {e}")
        
        routes_data["total_apis"] = len(routes_data["apis_with_routes"])
        
        # Save single combined file
        filename = "apigw_routes.json"
        if api_id:
            filename = f"apigw_routes_{api_id}.json"
        
        filepath = _save_json_file(output_dir, filename, routes_data)
        if filepath:
            print(f"\n[✓] Saved routes → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

