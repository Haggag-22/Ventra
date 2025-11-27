"""
CloudWatch Dashboards Collector
Collects CloudWatch dashboard configurations.
Not critical but nice to store as evidence.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_cloudwatch_client(region):
    """CloudWatch client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("cloudwatch")


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


def run_cloudwatch_dashboards(args):
    """Collect CloudWatch dashboards."""
    print(f"[+] CloudWatch Dashboards Collector")
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
        cw_client = _get_cloudwatch_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch client: {e}")
        return
    
    try:
        dashboards_data = {
            "dashboards": [],
        }
        
        print("[+] Listing all dashboards...")
        response = cw_client.list_dashboards()
        
        for dashboard in response.get("DashboardEntries", []):
            dashboard_name = dashboard.get("DashboardName")
            
            dashboard_info = {
                "DashboardName": dashboard_name,
                "DashboardArn": dashboard.get("DashboardArn"),
                "LastModified": str(dashboard.get("LastModified", "")),
                "Size": dashboard.get("Size", 0),
            }
            
            # Get dashboard body
            try:
                dashboard_response = cw_client.get_dashboard(DashboardName=dashboard_name)
                dashboard_info["DashboardBody"] = dashboard_response.get("DashboardBody")
            except ClientError as e:
                print(f"      ⚠ Error getting dashboard body for {dashboard_name}: {e}")
                dashboard_info["DashboardBody"] = None
            
            dashboards_data["dashboards"].append(dashboard_info)
        
        dashboards_data["total_dashboards"] = len(dashboards_data["dashboards"])
        print(f"    ✓ Found {dashboards_data['total_dashboards']} dashboard(s)")
        
        # Save single combined file
        filename = "cloudwatch_dashboards.json"
        filepath = _save_json_file(output_dir, filename, dashboards_data)
        if filepath:
            print(f"\n[✓] Saved dashboards → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

