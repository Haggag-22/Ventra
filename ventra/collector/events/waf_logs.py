"""
WAF (Web Application Firewall) Logs Collector
Collects WAF log configurations and events.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_wafv2_client(region):
    """WAF v2 client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("wafv2")


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


def run_waf_logs(args):
    """Collect WAF log configurations."""
    print(f"[+] WAF Logs Collector")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "events")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        wafv2_client = _get_wafv2_client(args.region)
    except Exception as e:
        print(f"❌ Error getting WAF v2 client: {e}")
        return
    
    waf_data = {
        "web_acls": [],
        "log_configurations": [],
    }
    
    try:
        print("[+] Listing Web ACLs...")
        
        # List Web ACLs (scope can be CLOUDFRONT or REGIONAL)
        for scope in ["CLOUDFRONT", "REGIONAL"]:
            try:
                paginator = wafv2_client.get_paginator("list_web_acls")
                for page in paginator.paginate(Scope=scope):
                    for acl_summary in page.get("WebACLs", []):
                        acl_id = acl_summary.get("Id")
                        acl_name = acl_summary.get("Name")
                        acl_arn = acl_summary.get("ARN")
                        
                        print(f"    Processing: {acl_name} ({scope})")
                        
                        # Get Web ACL details
                        try:
                            acl_response = wafv2_client.get_web_acl(
                                Scope=scope,
                                Id=acl_id,
                                Name=acl_name
                            )
                            acl = acl_response.get("WebACL", {})
                            
                            acl_info = {
                                "Id": acl_id,
                                "Name": acl_name,
                                "ARN": acl_arn,
                                "Scope": scope,
                                "DefaultAction": acl.get("DefaultAction", {}),
                                "Rules": acl.get("Rules", []),
                                "VisibilityConfig": acl.get("VisibilityConfig", {}),
                                "Capacity": acl.get("Capacity"),
                            }
                            
                            # Get logging configuration
                            try:
                                log_config_response = wafv2_client.get_logging_configuration(
                                    ResourceArn=acl_arn
                                )
                                log_config = log_config_response.get("LoggingConfiguration", {})
                                acl_info["LoggingConfiguration"] = log_config
                                waf_data["log_configurations"].append(log_config)
                                print(f"      ✓ Logging configured")
                            except ClientError as e:
                                if e.response.get("Error", {}).get("Code") == "WAFNonexistentItemException":
                                    acl_info["LoggingConfiguration"] = None
                                    print(f"      ⚠ Logging not configured")
                                else:
                                    print(f"      ⚠ Error getting logging config: {e}")
                            
                            waf_data["web_acls"].append(acl_info)
                        except ClientError as e:
                            print(f"      ⚠ Error getting Web ACL details: {e}")
            except ClientError as e:
                if "not available" not in str(e).lower():
                    print(f"    ⚠ Error listing {scope} Web ACLs: {e}")
        
        if not waf_data["web_acls"]:
            print("    ⚠ No Web ACLs found")
            return
        
        print(f"    ✓ Found {len(waf_data['web_acls'])} Web ACL(s)")
        print(f"    ✓ Found {len(waf_data['log_configurations'])} logging configuration(s)")
        
        # Save to file
        filename = "waf_logs.json"
        filepath = _save_json_file(output_dir, filename, waf_data)
        
        if filepath:
            print(f"\n[✓] Saved WAF log configurations → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

