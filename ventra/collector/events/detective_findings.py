"""
Amazon Detective Findings Collector (Optional)
Collects security findings and insights from Amazon Detective.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_detective_client(region):
    """Detective client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("detective")


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


def run_detective_findings(args):
    """Collect Amazon Detective findings."""
    print(f"[+] Amazon Detective Findings Collector")
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
        detective_client = _get_detective_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Detective client: {e}")
        return
    
    detective_data = {
        "graphs": [],
        "findings": [],
    }
    
    try:
        print("[+] Listing Detective graphs...")
        
        paginator = detective_client.get_paginator("list_graphs")
        graph_arns = []
        
        for page in paginator.paginate():
            for graph in page.get("GraphList", []):
                graph_arn = graph.get("GraphArn")
                graph_arns.append(graph_arn)
                
                graph_info = {
                    "GraphArn": graph_arn,
                    "CreatedTime": str(graph.get("CreatedTime", "")),
                }
                
                print(f"    Processing graph: {graph_arn}")
                
                # Get graph details
                try:
                    graph_response = detective_client.get_graph(GraphArn=graph_arn)
                    graph_info.update({
                        "Tags": graph_response.get("Tags", {}),
                    })
                except ClientError as e:
                    print(f"      ⚠ Error getting graph details: {e}")
                
                # List findings
                try:
                    findings_paginator = detective_client.get_paginator("list_findings")
                    graph_findings = []
                    
                    for findings_page in findings_paginator.paginate(GraphArn=graph_arn):
                        for finding in findings_page.get("Findings", []):
                            finding_id = finding.get("Id")
                            
                            # Get finding details
                            try:
                                finding_response = detective_client.get_findings(
                                    GraphArn=graph_arn,
                                    FindingIds=[finding_id]
                                )
                                finding_details = finding_response.get("Findings", [])
                                if finding_details:
                                    graph_findings.extend(finding_details)
                            except ClientError as e:
                                print(f"        ⚠ Error getting finding {finding_id}: {e}")
                    
                    graph_info["Findings"] = graph_findings
                    graph_info["FindingCount"] = len(graph_findings)
                    detective_data["findings"].extend(graph_findings)
                    
                    if graph_findings:
                        print(f"      ✓ Found {len(graph_findings)} finding(s)")
                    else:
                        print(f"      ⚠ No findings")
                except ClientError as e:
                    print(f"      ⚠ Error listing findings: {e}")
                    graph_info["Findings"] = []
                    graph_info["FindingCount"] = 0
                
                detective_data["graphs"].append(graph_info)
        
        if not graph_arns:
            print("    ⚠ No Detective graphs found (Detective may not be enabled)")
            return
        
        print(f"    ✓ Found {len(graph_arns)} graph(s)")
        print(f"    ✓ Found {len(detective_data['findings'])} total finding(s)")
        
        # Save to file
        filename = "detective_findings.json"
        filepath = _save_json_file(output_dir, filename, detective_data)
        
        if filepath:
            print(f"\n[✓] Saved Detective findings → {filepath}\n")
        
    except ClientError as e:
        if "not enabled" in str(e).lower() or "not found" in str(e).lower():
            print(f"    ⚠ Amazon Detective is not enabled in this account/region")
        else:
            print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

