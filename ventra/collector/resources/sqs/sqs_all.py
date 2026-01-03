"""
SQS All Collector
Collects all SQS information (queues and sample messages) into a single combined file.
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


def run_sqs_all(args):
    """Collect all SQS data (queues and sample messages) into a single file."""
    print(f"[+] SQS All Collector")
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
        all_data = {
            "Queues": [],
        }
        
        # Collect all queues with their attributes, tags, and sample messages
        print("[+] Listing all SQS queues...")
        try:
            response = sqs_client.list_queues()
            queue_urls = response.get("QueueUrls", [])
            
            print(f"    ✓ Found {len(queue_urls)} queue(s)")
            
            for queue_url in queue_urls:
                queue_name = queue_url.split("/")[-1]
                print(f"[+] Collecting details for queue: {queue_name}")
                
                queue_info = {
                    "QueueUrl": queue_url,
                    "QueueName": queue_name,
                    "Attributes": {},
                    "Tags": {},
                    "SampleMessages": [],
                }
                
                # Get queue attributes
                try:
                    attrs = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=["All"]
                    )
                    queue_info["Attributes"] = attrs.get("Attributes", {})
                except Exception as e:
                    print(f"      ⚠ Error getting attributes: {e} (continuing)")
                
                # Get queue tags
                try:
                    tags = sqs_client.list_queue_tags(QueueUrl=queue_url)
                    queue_info["Tags"] = tags.get("Tags", {})
                except Exception as e:
                    print(f"      ⚠ Error getting tags: {e} (continuing)")
                
                # Get sample messages (up to 10)
                try:
                    messages_response = sqs_client.receive_message(
                        QueueUrl=queue_url,
                        MaxNumberOfMessages=10,
                        AttributeNames=["All"],
                        MessageAttributeNames=["All"]
                    )
                    messages = messages_response.get("Messages", [])
                    for msg in messages:
                        msg_info = {
                            "MessageId": msg.get("MessageId"),
                            "ReceiptHandle": msg.get("ReceiptHandle"),
                            "Body": msg.get("Body"),
                            "Attributes": msg.get("Attributes", {}),
                            "MessageAttributes": msg.get("MessageAttributes", {}),
                        }
                        queue_info["SampleMessages"].append(msg_info)
                    
                    if messages:
                        print(f"      ✓ Collected {len(messages)} sample message(s)")
                except Exception as e:
                    print(f"      ⚠ Error getting sample messages: {e} (continuing)")
                
                all_data["Queues"].append(queue_info)
            
            total_messages = sum(len(q["SampleMessages"]) for q in all_data["Queues"])
            all_data["total_queues"] = len(all_data["Queues"])
            all_data["total_sample_messages"] = total_messages
            
        except Exception as e:
            print(f"    ⚠ Error collecting queues: {e} (continuing)")
        
        # Save combined file
        filename = "sqs_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all SQS data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

