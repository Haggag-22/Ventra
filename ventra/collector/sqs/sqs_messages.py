"""
SQS Messages Collector
Collects sample messages from SQS queues.
Attackers hide payloads in queues - this is critical for DFIR.
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


def run_sqs_messages(args):
    """Collect sample messages from SQS queues."""
    sample = getattr(args, "sample", True)
    queue_url = getattr(args, "queue", None)
    
    print(f"[+] SQS Messages Collector")
    if queue_url:
        print(f"    Queue:       {queue_url}")
    else:
        print(f"    All Queues:  Yes")
    print(f"    Sample:      {sample}")
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
        messages_data = {
            "queues_with_messages": [],
        }
        
        # Get queue URLs
        if queue_url:
            queue_urls = [queue_url]
        else:
            print("[+] Listing all SQS queues...")
            response = sqs_client.list_queues()
            queue_urls = response.get("QueueUrls", [])
            print(f"    ✓ Found {len(queue_urls)} queue(s)")
        
        # Sample messages from each queue
        for queue_url_item in queue_urls:
            queue_name = queue_url_item.split("/")[-1]
            print(f"[+] Sampling messages from queue: {queue_name}")
            
            try:
                # Receive messages (max 10 per call, sample mode)
                max_messages = 10 if sample else 1
                messages_response = sqs_client.receive_message(
                    QueueUrl=queue_url_item,
                    MaxNumberOfMessages=max_messages,
                    AttributeNames=["All"],
                    MessageAttributeNames=["All"]
                )
                
                messages = messages_response.get("Messages", [])
                
                if messages:
                    queue_messages_info = {
                        "QueueUrl": queue_url_item,
                        "QueueName": queue_name,
                        "Messages": [],
                    }
                    
                    for msg in messages:
                        message_info = {
                            "MessageId": msg.get("MessageId"),
                            "ReceiptHandle": msg.get("ReceiptHandle"),
                            "Body": msg.get("Body"),
                            "Attributes": msg.get("Attributes", {}),
                            "MessageAttributes": msg.get("MessageAttributes", {}),
                            "MD5OfBody": msg.get("MD5OfBody"),
                        }
                        queue_messages_info["Messages"].append(message_info)
                    
                    messages_data["queues_with_messages"].append(queue_messages_info)
                    print(f"    ✓ Sampled {len(messages)} message(s)")
                else:
                    print(f"    ⚠ No messages in queue")
                    
            except ClientError as e:
                print(f"      ⚠ Error receiving messages: {e}")
        
        messages_data["total_queues_checked"] = len(queue_urls)
        messages_data["total_queues_with_messages"] = len(messages_data["queues_with_messages"])
        total_messages = sum(len(q["Messages"]) for q in messages_data["queues_with_messages"])
        messages_data["total_messages"] = total_messages
        
        print(f"\n    Summary: {total_messages} message(s) sampled from {messages_data['total_queues_with_messages']} queue(s)")
        
        # Save single combined file
        filename = "sqs_messages.json"
        if queue_url:
            safe_name = queue_name.replace(":", "_").replace("/", "_")
            filename = f"sqs_messages_{safe_name}.json"
        
        filepath = _save_json_file(output_dir, filename, messages_data)
        if filepath:
            print(f"\n[✓] Saved messages → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

