"""
CloudFront Access Logs Collector (Optional)
Collects CloudFront distribution access log configurations.
Note: CloudFront logs are stored in S3, this collector identifies distributions with logging enabled.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_cloudfront_client():
    """CloudFront client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name="us-east-1",  # CloudFront is global, but API is in us-east-1
    )
    return session.client("cloudfront")


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


def run_cloudfront_access_logs(args):
    """Collect CloudFront access log configurations."""
    print(f"[+] CloudFront Access Logs Collector")
    print(f"    Region:      us-east-1 (CloudFront is global)\n")
    
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
        cloudfront_client = _get_cloudfront_client()
    except Exception as e:
        print(f"❌ Error getting CloudFront client: {e}")
        return
    
    try:
        print("[+] Listing CloudFront distributions...")
        paginator = cloudfront_client.get_paginator("list_distributions")
        all_distributions = []
        
        for page in paginator.paginate():
            for dist_summary in page.get("DistributionList", {}).get("Items", []):
                dist_id = dist_summary.get("Id")
                
                # Get full distribution details
                try:
                    dist_response = cloudfront_client.get_distribution(Id=dist_id)
                    distribution = dist_response.get("Distribution", {})
                    config = distribution.get("DistributionConfig", {})
                    
                    dist_info = {
                        "Id": dist_id,
                        "ARN": distribution.get("ARN"),
                        "DomainName": distribution.get("DomainName"),
                        "Status": distribution.get("Status"),
                        "Enabled": config.get("Enabled"),
                        "Comment": config.get("Comment", ""),
                        "Origins": config.get("Origins", {}).get("Items", []),
                    }
                    
                    # Extract logging configuration
                    logging_config = config.get("Logging", {})
                    dist_info["Logging"] = {
                        "Enabled": logging_config.get("Enabled", False),
                        "Bucket": logging_config.get("Bucket", ""),
                        "Prefix": logging_config.get("Prefix", ""),
                        "IncludeCookies": logging_config.get("IncludeCookies", False),
                    }
                    
                    if logging_config.get("Enabled"):
                        print(f"    ✓ {dist_id}: Logging enabled → s3://{logging_config.get('Bucket')}/{logging_config.get('Prefix')}")
                    else:
                        print(f"    ⚠ {dist_id}: Logging not enabled")
                    
                    all_distributions.append(dist_info)
                except ClientError as e:
                    print(f"    ⚠ Error getting distribution {dist_id}: {e}")
        
        if not all_distributions:
            print("    ⚠ No CloudFront distributions found")
            return
        
        print(f"    ✓ Found {len(all_distributions)} distribution(s)")
        
        # Save to file
        filename = "cloudfront_access_logs.json"
        filepath = _save_json_file(output_dir, filename, {
            "distributions": all_distributions,
            "total": len(all_distributions)
        })
        
        if filepath:
            print(f"\n[✓] Saved CloudFront access log configurations → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

