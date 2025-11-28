"""
GuardDuty All Collector
Collects all GuardDuty information (detectors, findings, malware) into a single combined file.
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


def run_guradduty_all(args):
    """Collect all GuardDuty data into a single file."""
    print(f"[+] GuardDuty All Collector")
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
        gd_client = _get_guardduty_client(args.region)
    except Exception as e:
        print(f"❌ Error getting GuardDuty client: {e}")
        return
    
    try:
        all_data = {
            "Detectors": [],
        }
        
        # 1. Collect detectors
        print("[+] Collecting GuardDuty detectors...")
        try:
            response = gd_client.list_detectors()
            detector_ids = response.get("DetectorIds", [])
            
            if not detector_ids:
                print("    ⚠ No detectors found in this region")
            else:
                print(f"    ✓ Found {len(detector_ids)} detector(s)")
                
                for detector_id in detector_ids:
                    print(f"[+] Processing detector: {detector_id}")
                    
                    detector_info = {
                        "DetectorId": detector_id,
                        "DetectorDetails": None,
                        "Findings": [],
                        "MalwareScans": [],
                    }
                    
                    # Get detector details
                    try:
                        detector = gd_client.get_detector(DetectorId=detector_id)
                        detector_info["DetectorDetails"] = {
                            "CreatedAt": str(detector.get("CreatedAt", "")),
                            "ServiceRole": detector.get("ServiceRole"),
                            "Status": detector.get("Status"),
                            "UpdatedAt": str(detector.get("UpdatedAt", "")),
                            "FindingPublishingFrequency": detector.get("FindingPublishingFrequency"),
                            "DataSources": detector.get("DataSources", {}),
                            "Tags": detector.get("Tags", {}),
                        }
                        print(f"    ✓ Collected detector details")
                    except Exception as e:
                        print(f"    ⚠ Error getting detector details: {e} (continuing)")
                    
                    # Get findings
                    print(f"    → Collecting findings...")
                    try:
                        paginator = gd_client.get_paginator("list_findings")
                        finding_ids = []
                        for page in paginator.paginate(DetectorId=detector_id):
                            finding_ids.extend(page.get("FindingIds", []))
                        
                        if finding_ids:
                            # Get findings in batches
                            for i in range(0, len(finding_ids), 50):
                                batch = finding_ids[i:i+50]
                                findings_response = gd_client.get_findings(
                                    DetectorId=detector_id,
                                    FindingIds=batch
                                )
                                detector_info["Findings"].extend(findings_response.get("Findings", []))
                        
                        print(f"      ✓ Found {len(detector_info['Findings'])} finding(s)")
                    except Exception as e:
                        print(f"      ⚠ Error collecting findings: {e} (continuing)")
                    
                    # Get malware scans
                    print(f"    → Collecting malware scans...")
                    try:
                        # Try list_ebs_snapshot_scan_results
                        try:
                            scan_paginator = gd_client.get_paginator("list_ebs_snapshot_scan_results")
                            for page in scan_paginator.paginate(DetectorId=detector_id):
                                for scan in page.get("ScanResults", []):
                                    scan_info = {
                                        "SnapshotId": scan.get("SnapshotId"),
                                        "VolumeId": scan.get("VolumeId"),
                                        "ScanId": scan.get("ScanId"),
                                        "ScanStartedAt": str(scan.get("ScanStartedAt", "")),
                                        "ScanCompletedAt": str(scan.get("ScanCompletedAt", "")),
                                        "FindingCount": scan.get("FindingCount", 0),
                                        "ThreatDetectedByName": scan.get("ThreatDetectedByName"),
                                        "ThreatNames": scan.get("ThreatNames", []),
                                    }
                                    detector_info["MalwareScans"].append(scan_info)
                        except Exception:
                            # Try malware findings
                            try:
                                findings_paginator = gd_client.get_paginator("list_findings")
                                for page in findings_paginator.paginate(
                                    DetectorId=detector_id,
                                    FindingCriteria={
                                        "Criterion": {
                                            "type": {"Eq": ["Malware:EC2/MalwareReconnaissance"]}
                                        }
                                    }
                                ):
                                    finding_ids = page.get("FindingIds", [])
                                    if finding_ids:
                                        findings = gd_client.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
                                        for finding in findings.get("Findings", []):
                                            if "Malware" in finding.get("Type", ""):
                                                detector_info["MalwareScans"].append({
                                                    "FindingId": finding.get("Id"),
                                                    "Type": finding.get("Type"),
                                                    "Severity": finding.get("Severity"),
                                                    "CreatedAt": str(finding.get("CreatedAt", "")),
                                                    "Resource": finding.get("Resource", {}),
                                                })
                            except Exception:
                                pass
                        
                        print(f"      ✓ Found {len(detector_info['MalwareScans'])} malware scan(s)")
                    except Exception as e:
                        print(f"      ⚠ Error collecting malware scans: {e} (continuing)")
                    
                    all_data["Detectors"].append(detector_info)
                    print()
        except Exception as e:
            print(f"    ⚠ Error collecting detectors: {e} (continuing)")
        
        # Summary
        all_data["total_detectors"] = len(all_data["Detectors"])
        total_findings = sum(len(d.get("Findings", [])) for d in all_data["Detectors"])
        total_malware_scans = sum(len(d.get("MalwareScans", [])) for d in all_data["Detectors"])
        
        all_data["total_findings"] = total_findings
        all_data["total_malware_scans"] = total_malware_scans
        
        # Count findings by severity
        severity_counts = {}
        for detector in all_data["Detectors"]:
            for finding in detector.get("Findings", []):
                sev = finding.get("Severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
        all_data["finding_severity_counts"] = severity_counts
        
        print(f"\n    Summary:")
        print(f"      Detectors: {all_data['total_detectors']}")
        print(f"      Findings: {total_findings}")
        print(f"      Malware Scans: {total_malware_scans}")
        
        # Save combined file
        filename = "guradduty_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all GuardDuty data → {filepath}\n")
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "BadRequestException":
            print(f"    ⚠ GuardDuty not available in this region")
        else:
            print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
