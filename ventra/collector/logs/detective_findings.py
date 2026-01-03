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
    
    output_dir = os.path.join(output_dir, "logs")
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

        # NOTE: Detective's list_graphs is not pageable in botocore, so do manual
        # NextToken pagination (works even when the API returns everything in one page).
        graph_arns = []
        graphs = []
        next_token = None
        while True:
            kwargs = {}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = detective_client.list_graphs(**kwargs)
            page_graphs = resp.get("GraphList", []) or []
            graphs.extend(page_graphs)
            next_token = resp.get("NextToken")
            if not next_token:
                break

        for graph in graphs:
            if isinstance(graph, str):
                graph_arn = graph
                created_time = ""
            else:
                graph_arn = graph.get("GraphArn")
                created_time = str(graph.get("CreatedTime", ""))

            if not graph_arn:
                continue

            graph_arns.append(graph_arn)

            graph_info = {
                "GraphArn": graph_arn,
                "CreatedTime": created_time,
            }

            print(f"    Processing graph: {graph_arn}")

            # Get graph details
            try:
                graph_response = detective_client.get_graph(GraphArn=graph_arn)
                graph_info.update(
                    {
                        "Tags": graph_response.get("Tags", {}),
                    }
                )
            except ClientError as e:
                print(f"      ⚠ Error getting graph details: {e}")

            # List findings
            try:
                # list_findings is also not pageable in some botocore versions.
                # Do manual NextToken pagination and then batch get_findings.
                finding_ids = []
                next_token = None
                while True:
                    kwargs = {"GraphArn": graph_arn}
                    if next_token:
                        kwargs["NextToken"] = next_token
                    resp = detective_client.list_findings(**kwargs)
                    for f in resp.get("Findings", []) or []:
                        if isinstance(f, str):
                            fid = f
                        else:
                            fid = f.get("Id")
                        if fid:
                            finding_ids.append(fid)
                    next_token = resp.get("NextToken")
                    if not next_token:
                        break

                graph_findings = []
                # get_findings supports batches (limit is typically 50)
                for i in range(0, len(finding_ids), 50):
                    batch = finding_ids[i : i + 50]
                    try:
                        finding_response = detective_client.get_findings(
                            GraphArn=graph_arn,
                            FindingIds=batch,
                        )
                        graph_findings.extend(finding_response.get("Findings", []) or [])
                    except ClientError as e:
                        print(f"        ⚠ Error getting findings batch ({len(batch)} ids): {e}")

                graph_info["Findings"] = graph_findings
                graph_info["FindingCount"] = len(graph_findings)
                detective_data["findings"].extend(graph_findings)

                if graph_findings:
                    print(f"      ✓ Found {len(graph_findings)} finding(s)")
                else:
                    print("      ⚠ No findings")
            except ClientError as e:
                print(f"      ⚠ Error listing findings: {e}")
                graph_info["Findings"] = []
                graph_info["FindingCount"] = 0

            detective_data["graphs"].append(graph_info)
        
        if not graph_arns:
            print("    ⚠ No Detective graphs found (Detective may not be enabled)")
            filename = "detective_findings.json"
            filepath = _save_json_file(output_dir, filename, {"message": "No Detective graphs found", **detective_data})
            if filepath:
                print(f"\n[✓] Saved status → {filepath}\n")
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
