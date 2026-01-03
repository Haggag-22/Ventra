"""
SNS Subscriptions Collector
Collects SNS subscriptions for all topics.
Attackers use subscriptions to exfiltrate data or trigger malicious workflows.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_sns_client(region):
    """SNS client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("sns")


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


def run_sns_subscriptions(args):
    """Collect SNS subscriptions."""
    print(f"[+] SNS Subscriptions Collector")
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
        sns_client = _get_sns_client(args.region)
    except Exception as e:
        print(f"❌ Error getting SNS client: {e}")
        return
    
    try:
        subscriptions_data = {
            "topics_with_subscriptions": [],
        }
        
        print("[+] Listing all SNS topics and their subscriptions...")
        paginator = sns_client.get_paginator("list_topics")
        topic_count = 0
        
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                topic_arn = topic.get("TopicArn")
                topic_count += 1
                
                try:
                    subs_paginator = sns_client.get_paginator("list_subscriptions_by_topic")
                    subscriptions = []
                    for subs_page in subs_paginator.paginate(TopicArn=topic_arn):
                        for sub in subs_page.get("Subscriptions", []):
                            sub_info = {
                                "SubscriptionArn": sub.get("SubscriptionArn"),
                                "Owner": sub.get("Owner"),
                                "Protocol": sub.get("Protocol"),
                                "Endpoint": sub.get("Endpoint"),
                                "TopicArn": sub.get("TopicArn"),
                            }
                            subscriptions.append(sub_info)
                    
                    if subscriptions:
                        topic_subs_info = {
                            "TopicArn": topic_arn,
                            "Subscriptions": subscriptions,
                        }
                        subscriptions_data["topics_with_subscriptions"].append(topic_subs_info)
                except ClientError as e:
                    print(f"      ⚠ Error getting subscriptions for {topic_arn}: {e}")
        
        subscriptions_data["total_topics_checked"] = topic_count
        subscriptions_data["total_topics_with_subscriptions"] = len(subscriptions_data["topics_with_subscriptions"])
        
        total_subs = sum(len(t["Subscriptions"]) for t in subscriptions_data["topics_with_subscriptions"])
        subscriptions_data["total_subscriptions"] = total_subs
        
        print(f"    ✓ Checked {topic_count} topic(s)")
        print(f"    ✓ Found {total_subs} subscription(s) across {subscriptions_data['total_topics_with_subscriptions']} topic(s)")
        
        # Save single combined file
        filename = "sns_subscriptions.json"
        filepath = _save_json_file(output_dir, filename, subscriptions_data)
        if filepath:
            print(f"\n[✓] Saved subscriptions → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

