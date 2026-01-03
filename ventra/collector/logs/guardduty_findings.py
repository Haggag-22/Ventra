"""
GuardDuty Findings Collector
Collects GuardDuty findings, optionally filtered by severity or resource.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_guardduty_client(region):
    """GuardDuty client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("guardduty")


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


def run_guardduty_findings(args):
    """Collect GuardDuty findings."""
    severity = getattr(args, "severity", None)
    resource = getattr(args, "resource", None)
    
    print(f"[+] GuardDuty Findings Collector")
    if severity:
        print(f"    Severity:    {severity}")
    if resource:
        print(f"    Resource:    {resource}")
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
    print(f"    Output:      {output_dir}\n")
    
    try:
        gd_client = _get_guardduty_client(args.region)
    except Exception as e:
        print(f"❌ Error getting GuardDuty client: {e}")
        return
    
    try:
        # List detectors first
        print("[+] Finding detectors...")
        response = gd_client.list_detectors()
        detector_ids = response.get("DetectorIds", [])
        
        if not detector_ids:
            print("    ⚠ No detectors found in this region")
            findings_data = {"detectors": [], "findings": []}
            filename = "guardduty_findings.json"
            filepath = _save_json_file(output_dir, filename, findings_data)
            if filepath:
                print(f"\n[✓] Saved findings → {filepath}\n")
            return
        
        print(f"    ✓ Found {len(detector_ids)} detector(s)")
        
        findings_data = {
            "detectors": detector_ids,
            "findings": [],
        }
        
        # Build filter criteria
        criteria = {}
        if severity:
            criteria["Severity"] = {"Eq": [severity.upper()]}
        if resource:
            criteria["ResourceAffected"] = {"Eq": [resource]}
        
        # Collect findings from all detectors
        for detector_id in detector_ids:
            print(f"[+] Collecting findings from detector: {detector_id}")
            
            try:
                if criteria:
                    # Use list_findings with criteria
                    paginator = gd_client.get_paginator("list_findings")
                    pages = paginator.paginate(
                        DetectorId=detector_id,
                        FindingCriteria={"Criterion": criteria}
                    )
                else:
                    # List all findings
                    paginator = gd_client.get_paginator("list_findings")
                    pages = paginator.paginate(DetectorId=detector_id)
                
                finding_ids = []
                for page in pages:
                    finding_ids.extend(page.get("FindingIds", []))
                
                print(f"    ✓ Found {len(finding_ids)} finding(s)")
                
                # Get finding details
                if finding_ids:
                    # Get findings in batches (max 50 per call)
                    for i in range(0, len(finding_ids), 50):
                        batch = finding_ids[i:i+50]
                        findings_response = gd_client.get_findings(
                            DetectorId=detector_id,
                            FindingIds=batch
                        )
                        findings_data["findings"].extend(findings_response.get("Findings", []))
                
            except ClientError as e:
                print(f"    ⚠ Error collecting findings: {e}")
        
        findings_data["total_findings"] = len(findings_data["findings"])
        
        # Count by severity
        severity_counts = {}
        for finding in findings_data["findings"]:
            sev = finding.get("Severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        findings_data["severity_counts"] = severity_counts
        
        print(f"\n    Summary:")
        print(f"      Total findings: {findings_data['total_findings']}")
        for sev, count in severity_counts.items():
            print(f"      {sev}: {count}")
        
        # Save single combined file
        filename = "guardduty_findings.json"
        if severity:
            filename = f"guardduty_findings_{severity.lower()}.json"
        if resource:
            safe_resource = resource.replace(":", "_").replace("/", "_")
            filename = f"guardduty_findings_{safe_resource}.json"
        
        filepath = _save_json_file(output_dir, filename, findings_data)
        if filepath:
            print(f"\n[✓] Saved findings → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

