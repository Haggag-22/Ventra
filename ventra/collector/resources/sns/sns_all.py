"""
SNS All Collector
Collects all SNS information (topics and subscriptions) into a single combined file.
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


def run_sns_all(args):
    """Collect all SNS data (topics and subscriptions) into a single file."""
    print(f"[+] SNS All Collector")
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
        all_data = {
            "Topics": [],
        }
        
        # Collect all topics with their subscriptions
        print("[+] Listing all SNS topics...")
        try:
            paginator = sns_client.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    topic_arn = topic.get("TopicArn")
                    
                    topic_info = {
                        "TopicArn": topic_arn,
                        "Attributes": {},
                        "Tags": {},
                        "Subscriptions": [],
                    }
                    
                    # Get topic attributes
                    try:
                        attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
                        topic_info["Attributes"] = attrs.get("Attributes", {})
                    except Exception as e:
                        print(f"      ⚠ Error getting attributes for {topic_arn}: {e} (continuing)")
                    
                    # Get topic tags
                    try:
                        tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
                        topic_info["Tags"] = {tag["Key"]: tag["Value"] for tag in tags.get("Tags", [])}
                    except Exception as e:
                        print(f"      ⚠ Error getting tags for {topic_arn}: {e} (continuing)")
                    
                    # Get subscriptions for this topic
                    try:
                        subs_paginator = sns_client.get_paginator("list_subscriptions_by_topic")
                        for subs_page in subs_paginator.paginate(TopicArn=topic_arn):
                            for sub in subs_page.get("Subscriptions", []):
                                sub_info = {
                                    "SubscriptionArn": sub.get("SubscriptionArn"),
                                    "Owner": sub.get("Owner"),
                                    "Protocol": sub.get("Protocol"),
                                    "Endpoint": sub.get("Endpoint"),
                                    "TopicArn": sub.get("TopicArn"),
                                }
                                topic_info["Subscriptions"].append(sub_info)
                    except Exception as e:
                        print(f"      ⚠ Error getting subscriptions for {topic_arn}: {e} (continuing)")
                    
                    all_data["Topics"].append(topic_info)
            
            total_subs = sum(len(t["Subscriptions"]) for t in all_data["Topics"])
            all_data["total_topics"] = len(all_data["Topics"])
            all_data["total_subscriptions"] = total_subs
            
            print(f"    ✓ Found {all_data['total_topics']} topic(s)")
            print(f"    ✓ Found {total_subs} subscription(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting topics: {e} (continuing)")
        
        # Save combined file
        filename = "sns_all.json"
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all SNS data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

