"""
SQS Queues Collector
Collects SQS queues and their configurations.
Attackers hide payloads in queues for persistence, exfiltration, and lateral movement.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_sqs_client(region):
    """SQS client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("sqs")


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


def run_sqs_queues(args):
    """Collect SQS queues."""
    print(f"[+] SQS Queues Collector")
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
        sqs_client = _get_sqs_client(args.region)
    except Exception as e:
        print(f"❌ Error getting SQS client: {e}")
        return
    
    try:
        queues_data = {
            "queues": [],
        }
        
        print("[+] Listing all SQS queues...")
        response = sqs_client.list_queues()
        queue_urls = response.get("QueueUrls", [])
        
        print(f"    ✓ Found {len(queue_urls)} queue(s)")
        
        # Get detailed information for each queue
        for queue_url in queue_urls:
            queue_name = queue_url.split("/")[-1]
            print(f"[+] Collecting details for queue: {queue_name}")
            
            try:
                # Get queue attributes
                attrs = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=["All"]
                )
                
                queue_info = {
                    "QueueUrl": queue_url,
                    "QueueName": queue_name,
                    "Attributes": attrs.get("Attributes", {}),
                }
                
                # Get queue tags
                try:
                    tags = sqs_client.list_queue_tags(QueueUrl=queue_url)
                    queue_info["Tags"] = tags.get("Tags", {})
                except ClientError as e:
                    queue_info["Tags"] = {}
                
                queues_data["queues"].append(queue_info)
                
            except ClientError as e:
                print(f"      ⚠ Error getting queue details: {e}")
        
        queues_data["total_queues"] = len(queues_data["queues"])
        
        # Save single combined file
        filename = "sqs_queues.json"
        filepath = _save_json_file(output_dir, filename, queues_data)
        if filepath:
            print(f"\n[✓] Saved queues → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

