"""
GuardDuty Collector Module
Collects GuardDuty findings, detectors, and threat intelligence feeds.
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


def collect_detectors(guardduty_client):
    """Collect all GuardDuty detectors."""
    detectors = []
    try:
        response = guardduty_client.list_detectors()
        detector_ids = response.get("DetectorIds", [])
        
        for detector_id in detector_ids:
            try:
                detector = guardduty_client.get_detector(DetectorId=detector_id)
                detectors.append({
                    "DetectorId": detector_id,
                    "CreatedAt": str(detector.get("CreatedAt", "")),
                    "ServiceRole": detector.get("ServiceRole"),
                    "Status": detector.get("Status"),
                    "UpdatedAt": str(detector.get("UpdatedAt", "")),
                    "FindingPublishingFrequency": detector.get("FindingPublishingFrequency"),
                    "DataSources": detector.get("DataSources", {}),
                    "Tags": detector.get("Tags", {}),
                })
            except ClientError as e:
                print(f"      ⚠ Error getting detector {detector_id}: {e}")
    except ClientError as e:
        print(f"    ❌ Error listing detectors: {e}")
    
    return detectors


def collect_findings(guardduty_client, detector_id, severity=None, max_results=None):
    """Collect GuardDuty findings for a detector."""
    findings = []
    try:
        finding_criteria = {}
        if severity:
            finding_criteria["Criterion"] = {
                "severity": {
                    "Eq": [severity]
                }
            }
        
        paginator = guardduty_client.get_paginator("list_findings")
        page_iterator = paginator.paginate(
            DetectorId=detector_id,
            FindingCriteria=finding_criteria if finding_criteria else {},
            SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
        )
        
        count = 0
        for page in page_iterator:
            finding_ids = page.get("FindingIds", [])
            
            if finding_ids:
                # Get detailed findings
                findings_response = guardduty_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids
                )
                
                for finding in findings_response.get("Findings", []):
                    findings.append({
                        "Id": finding.get("Id"),
                        "AccountId": finding.get("AccountId"),
                        "Region": finding.get("Region"),
                        "Type": finding.get("Type"),
                        "CreatedAt": str(finding.get("CreatedAt", "")),
                        "UpdatedAt": str(finding.get("UpdatedAt", "")),
                        "Title": finding.get("Title"),
                        "Description": finding.get("Description"),
                        "Severity": finding.get("Severity"),
                        "Service": finding.get("Service", {}),
                        "Resource": finding.get("Resource", {}),
                        "SchemaVersion": finding.get("SchemaVersion"),
                        "Partition": finding.get("Partition"),
                    })
                    count += 1
                    
                    if max_results and count >= max_results:
                        break
            
            if max_results and count >= max_results:
                break
                
    except ClientError as e:
        print(f"    ⚠ Error listing findings: {e}")
    
    return findings


def collect_threat_intelligence_sets(guardduty_client, detector_id):
    """Collect threat intelligence sets."""
    threat_intel_sets = []
    try:
        response = guardduty_client.list_threat_intel_sets(DetectorId=detector_id)
        threat_intel_set_ids = response.get("ThreatIntelSetIds", [])
        
        for threat_intel_set_id in threat_intel_set_ids:
            try:
                threat_intel_set = guardduty_client.get_threat_intel_set(
                    DetectorId=detector_id,
                    ThreatIntelSetId=threat_intel_set_id
                )
                threat_intel_sets.append({
                    "ThreatIntelSetId": threat_intel_set_id,
                    "Name": threat_intel_set.get("Name"),
                    "Format": threat_intel_set.get("Format"),
                    "Location": threat_intel_set.get("Location"),
                    "Status": threat_intel_set.get("Status"),
                    "Tags": threat_intel_set.get("Tags", {}),
                })
            except ClientError as e:
                print(f"      ⚠ Error getting threat intel set {threat_intel_set_id}: {e}")
    except ClientError as e:
        print(f"    ⚠ Error listing threat intel sets: {e}")
    
    return threat_intel_sets


def collect_ip_sets(guardduty_client, detector_id):
    """Collect IP sets."""
    ip_sets = []
    try:
        response = guardduty_client.list_ip_sets(DetectorId=detector_id)
        ip_set_ids = response.get("IpSetIds", [])
        
        for ip_set_id in ip_set_ids:
            try:
                ip_set = guardduty_client.get_ip_set(
                    DetectorId=detector_id,
                    IpSetId=ip_set_id
                )
                ip_sets.append({
                    "IpSetId": ip_set_id,
                    "Name": ip_set.get("Name"),
                    "Format": ip_set.get("Format"),
                    "Location": ip_set.get("Location"),
                    "Status": ip_set.get("Status"),
                    "Tags": ip_set.get("Tags", {}),
                })
            except ClientError as e:
                print(f"      ⚠ Error getting IP set {ip_set_id}: {e}")
    except ClientError as e:
        print(f"    ⚠ Error listing IP sets: {e}")
    
    return ip_sets


def run_guradduty_all(args):
    """Collect all GuardDuty information."""
    severity = getattr(args, "severity", None)
    max_findings = getattr(args, "max_findings", None)
    
    print(f"[+] GuardDuty Collector")
    print(f"    Region:      {args.region}")
    if severity:
        print(f"    Severity Filter: {severity}")
    if max_findings:
        print(f"    Max Findings: {max_findings}")
    print()
    
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
        guardduty_client = _get_guardduty_client(args.region)
    except Exception as e:
        print(f"❌ Error getting GuardDuty client: {e}")
        return
    
    try:
        all_data = {}
        
        print("[+] Collecting detectors...")
        detectors = collect_detectors(guardduty_client)
        all_data["detectors"] = detectors
        print(f"    ✓ Found {len(detectors)} detector(s)")
        
        # Collect findings and other data for each detector
        all_data["detector_details"] = []
        
        for detector in detectors:
            detector_id = detector.get("DetectorId")
            print(f"\n[+] Processing detector: {detector_id}")
            
            detector_detail = {
                "DetectorId": detector_id,
                "DetectorInfo": detector,
            }
            
            print(f"  [+] Collecting findings...")
            findings = collect_findings(guardduty_client, detector_id, severity, max_findings)
            detector_detail["findings"] = findings
            print(f"    ✓ Found {len(findings)} finding(s)")
            
            print(f"  [+] Collecting threat intelligence sets...")
            threat_intel_sets = collect_threat_intelligence_sets(guardduty_client, detector_id)
            detector_detail["threat_intelligence_sets"] = threat_intel_sets
            print(f"    ✓ Found {len(threat_intel_sets)} threat intel set(s)")
            
            print(f"  [+] Collecting IP sets...")
            ip_sets = collect_ip_sets(guardduty_client, detector_id)
            detector_detail["ip_sets"] = ip_sets
            print(f"    ✓ Found {len(ip_sets)} IP set(s)")
            
            all_data["detector_details"].append(detector_detail)
        
        # Save single combined file
        filename = "guradduty_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved GuardDuty data → {filepath}\n")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

