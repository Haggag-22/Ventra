"""
SNS Topics Collector
Collects SNS topics and their configurations.
Attackers use SNS for persistence, exfiltration, and lateral movement.
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


def run_sns_topics(args):
    """Collect SNS topics."""
    print(f"[+] SNS Topics Collector")
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
        topics_data = {
            "topics": [],
        }
        
        print("[+] Listing all SNS topics...")
        paginator = sns_client.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                topic_arn = topic.get("TopicArn")
                
                topic_info = {
                    "TopicArn": topic_arn,
                }
                
                # Get topic attributes
                try:
                    attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
                    topic_info["Attributes"] = attrs.get("Attributes", {})
                except ClientError as e:
                    print(f"      ⚠ Error getting attributes for {topic_arn}: {e}")
                    topic_info["Attributes"] = {}
                
                # Get topic tags
                try:
                    tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
                    topic_info["Tags"] = {tag["Key"]: tag["Value"] for tag in tags.get("Tags", [])}
                except ClientError as e:
                    topic_info["Tags"] = {}
                
                topics_data["topics"].append(topic_info)
        
        topics_data["total_topics"] = len(topics_data["topics"])
        print(f"    ✓ Found {topics_data['total_topics']} topic(s)")
        
        # Save single combined file
        filename = "sns_topics.json"
        filepath = _save_json_file(output_dir, filename, topics_data)
        if filepath:
            print(f"\n[✓] Saved topics → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

