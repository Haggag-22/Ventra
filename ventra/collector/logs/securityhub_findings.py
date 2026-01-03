"""
Security Hub Findings Collector
Collects Security Hub findings - unified findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, and Config compliance.
Useful during incident reports.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_securityhub_client(region):
    """Security Hub client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("securityhub")


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


def run_securityhub_findings(args):
    """Collect Security Hub findings."""
    severity = getattr(args, "severity", None)
    compliance_status = getattr(args, "compliance_status", None)
    
    print(f"[+] Security Hub Findings Collector")
    if severity:
        print(f"    Severity:    {severity}")
    if compliance_status:
        print(f"    Compliance:  {compliance_status}")
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
        securityhub_client = _get_securityhub_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Security Hub client: {e}")
        return
    
    try:
        # Check if Security Hub is enabled
        print("[+] Checking Security Hub status...")
        try:
            hubs = securityhub_client.describe_hub()
            print("    ✓ Security Hub is enabled")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "InvalidAccessException":
                print("    ⚠ Security Hub is not enabled in this region")
                findings_data = {"message": "Security Hub is not enabled"}
                filename = "securityhub_findings.json"
                filepath = _save_json_file(output_dir, filename, findings_data)
                if filepath:
                    print(f"\n[✓] Saved status → {filepath}\n")
                return
            else:
                raise
        
        findings_data = {
            "findings": [],
        }
        
        # Build filters
        filters = {}
        if severity:
            filters["SeverityLabel"] = [{"Value": severity.upper(), "Comparison": "EQUALS"}]
        if compliance_status:
            filters["ComplianceStatus"] = [{"Value": compliance_status.upper(), "Comparison": "EQUALS"}]
        
        print("[+] Collecting findings...")
        paginator = securityhub_client.get_paginator("get_findings")
        page_iterator = paginator.paginate(Filters=filters if filters else {})
        
        finding_count = 0
        for page in page_iterator:
            for finding in page.get("Findings", []):
                finding_info = {
                    "Id": finding.get("Id"),
                    "ProductArn": finding.get("ProductArn"),
                    "GeneratorId": finding.get("GeneratorId"),
                    "AwsAccountId": finding.get("AwsAccountId"),
                    "Types": finding.get("Types", []),
                    "FirstObservedAt": str(finding.get("FirstObservedAt", "")),
                    "LastObservedAt": str(finding.get("LastObservedAt", "")),
                    "CreatedAt": str(finding.get("CreatedAt", "")),
                    "UpdatedAt": str(finding.get("UpdatedAt", "")),
                    "Severity": finding.get("Severity", {}),
                    "Confidence": finding.get("Confidence"),
                    "Criticality": finding.get("Criticality"),
                    "Title": finding.get("Title"),
                    "Description": finding.get("Description"),
                    "Remediation": finding.get("Remediation", {}),
                    "SourceUrl": finding.get("SourceUrl"),
                    "ProductFields": finding.get("ProductFields", {}),
                    "UserDefinedFields": finding.get("UserDefinedFields", {}),
                    "Resources": finding.get("Resources", []),
                    "Compliance": finding.get("Compliance", {}),
                    "VerificationState": finding.get("VerificationState"),
                    "WorkflowState": finding.get("WorkflowState"),
                    "Workflow": finding.get("Workflow", {}),
                    "RecordState": finding.get("RecordState"),
                    "RelatedFindings": finding.get("RelatedFindings", []),
                    "Note": finding.get("Note", {}),
                }
                findings_data["findings"].append(finding_info)
                finding_count += 1
                
                if finding_count % 100 == 0:
                    print(f"    ... Collected {finding_count} findings so far...")
        
        findings_data["total_findings"] = len(findings_data["findings"])
        
        # Count by severity
        severity_counts = {}
        for finding in findings_data["findings"]:
            sev_label = finding.get("Severity", {}).get("Label", "UNKNOWN")
            severity_counts[sev_label] = severity_counts.get(sev_label, 0) + 1
        
        findings_data["severity_counts"] = severity_counts
        
        # Count by product (source)
        product_counts = {}
        for finding in findings_data["findings"]:
            product_arn = finding.get("ProductArn", "")
            # Extract product name from ARN
            if "guardduty" in product_arn.lower():
                product = "GuardDuty"
            elif "inspector" in product_arn.lower():
                product = "Inspector"
            elif "macie" in product_arn.lower():
                product = "Macie"
            elif "access-analyzer" in product_arn.lower():
                product = "IAM Access Analyzer"
            elif "config" in product_arn.lower():
                product = "Config"
            else:
                product = "Other"
            product_counts[product] = product_counts.get(product, 0) + 1
        
        findings_data["product_counts"] = product_counts
        
        print(f"\n    Summary:")
        print(f"      Total findings: {findings_data['total_findings']}")
        for sev, count in severity_counts.items():
            print(f"      {sev}: {count}")
        for product, count in product_counts.items():
            print(f"      {product}: {count}")
        
        # Save single combined file
        filename = "securityhub_findings.json"
        if severity:
            filename = f"securityhub_findings_{severity.lower()}.json"
        
        filepath = _save_json_file(output_dir, filename, findings_data)
        if filepath:
            print(f"\n[✓] Saved findings → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

