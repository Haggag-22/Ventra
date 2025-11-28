"""
API Gateway All Collector
Collects all API Gateway data (REST APIs info, routes, and integrations) into a single combined file.
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


def _collect_api_info(apigw_client, api_id):
    """Collect REST API information for a specific API."""
    try:
        response = apigw_client.get_rest_api(restApiId=api_id)
        return {
            "Id": api_id,
            "Name": response.get("name"),
            "Description": response.get("description"),
            "CreatedDate": str(response.get("createdDate", "")),
            "Version": response.get("version"),
            "Warnings": response.get("warnings", []),
            "BinaryMediaTypes": response.get("binaryMediaTypes", []),
            "MinimumCompressionSize": response.get("minimumCompressionSize"),
            "ApiKeySource": response.get("apiKeySource"),
            "EndpointConfiguration": response.get("endpointConfiguration", {}),
            "Policy": response.get("policy"),
            "Tags": response.get("tags", {}),
        }
    except ClientError as e:
        print(f"      ⚠ Error getting API info: {e}")
        return None


def _collect_routes(apigw_client, api_id):
    """Collect routes (resources and methods) for an API."""
    resources = []
    
    try:
        position = None
        while True:
            kwargs = {"restApiId": api_id, "limit": 500}
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
                            restApiId=api_id,
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
                
                resources.append(resource_info)
            
            position = resources_response.get("position")
            if not position:
                break
        
    except ClientError as e:
        print(f"      ⚠ Error getting routes: {e}")
    
    return resources


def _collect_integrations(apigw_client, api_id):
    """Collect integrations for an API."""
    integrations = []
    
    try:
        position = None
        while True:
            kwargs = {"restApiId": api_id, "limit": 500}
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
                            restApiId=api_id,
                            resourceId=resource_id,
                            httpMethod=method
                        )
                        
                        integration_info = {
                            "ApiId": api_id,
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
                        
                        integrations.append(integration_info)
                        
                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "")
                        if error_code != "NotFoundException":
                            print(f"      ⚠ Error getting integration for {method}: {e}")
            
            position = resources_response.get("position")
            if not position:
                break
        
    except ClientError as e:
        print(f"      ⚠ Error getting integrations: {e}")
    
    return integrations


def run_apigw_all(args):
    """Collect all API Gateway data for one or all APIs into a single file."""
    api_id = getattr(args, "api_id", None)
    
    print(f"[+] API Gateway All Collector")
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
        # Get API IDs to process
        if api_id:
            api_ids = [api_id]
        else:
            print("[+] Listing all REST APIs...")
            position = None
            api_ids = []
            while True:
                kwargs = {"limit": 500}
                if position:
                    kwargs["position"] = position
                
                response = apigw_client.get_rest_apis(**kwargs)
                api_ids.extend([api.get("id") for api in response.get("items", [])])
                
                position = response.get("position")
                if not position:
                    break
            
            print(f"    ✓ Found {len(api_ids)} API(s)\n")
        
        # Collect all data for each API
        all_data = {
            "apis": []
        }
        
        for api_id_item in api_ids:
            print(f"[+] Collecting all data for API: {api_id_item}")
            
            api_data = {
                "ApiId": api_id_item,
                "ApiInfo": None,
                "Routes": {
                    "Resources": []
                },
                "Integrations": {
                    "Integrations": []
                }
            }
            
            # Collect API info
            print(f"    → Collecting API info...")
            try:
                api_data["ApiInfo"] = _collect_api_info(apigw_client, api_id_item)
            except Exception as e:
                print(f"      ⚠ Error collecting API info: {e} (continuing)")
                api_data["ApiInfo"] = None
            
            # Collect routes
            print(f"    → Collecting routes...")
            try:
                api_data["Routes"]["Resources"] = _collect_routes(apigw_client, api_id_item)
                print(f"      ✓ Collected {len(api_data['Routes']['Resources'])} resource(s)")
            except Exception as e:
                print(f"      ⚠ Error collecting routes: {e} (continuing)")
                api_data["Routes"]["Resources"] = []
            
            # Collect integrations
            print(f"    → Collecting integrations...")
            try:
                api_data["Integrations"]["Integrations"] = _collect_integrations(apigw_client, api_id_item)
                print(f"      ✓ Collected {len(api_data['Integrations']['Integrations'])} integration(s)")
            except Exception as e:
                print(f"      ⚠ Error collecting integrations: {e} (continuing)")
                api_data["Integrations"]["Integrations"] = []
            
            all_data["apis"].append(api_data)
            print()
        
        all_data["total_apis"] = len(all_data["apis"])
        
        # Determine filename
        if api_id:
            filename = f"apigw_{api_id}_all.json"
        else:
            filename = "apigw_all.json"
        
        # Save combined file
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"[✓] Saved all API Gateway data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
