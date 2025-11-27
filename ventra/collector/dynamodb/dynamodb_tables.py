"""
DynamoDB Tables Collector
Collects DynamoDB tables and their configurations.
Attackers often use DynamoDB for persistence: stolen credentials, C2 beacons, automation state, event payloads, malicious scripts.
"""
import os
import json
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_dynamodb_client(region):
    """DynamoDB client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("dynamodb")


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


def run_dynamodb_tables(args):
    """Collect DynamoDB tables."""
    print(f"[+] DynamoDB Tables Collector")
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
        dynamodb_client = _get_dynamodb_client(args.region)
    except Exception as e:
        print(f"❌ Error getting DynamoDB client: {e}")
        return
    
    try:
        tables_data = {
            "tables": [],
        }
        
        print("[+] Listing all DynamoDB tables...")
        paginator = dynamodb_client.get_paginator("list_tables")
        table_names = []
        for page in paginator.paginate():
            table_names.extend(page.get("TableNames", []))
        
        print(f"    ✓ Found {len(table_names)} table(s)")
        
        # Get detailed information for each table
        for table_name in table_names:
            print(f"[+] Collecting details for table: {table_name}")
            try:
                # Describe table
                table_response = dynamodb_client.describe_table(TableName=table_name)
                table_desc = table_response.get("Table", {})
                
                table_info = {
                    "TableName": table_desc.get("TableName"),
                    "TableArn": table_desc.get("TableArn"),
                    "TableStatus": table_desc.get("TableStatus"),
                    "CreationDateTime": str(table_desc.get("CreationDateTime", "")),
                    "TableSizeBytes": table_desc.get("TableSizeBytes", 0),
                    "ItemCount": table_desc.get("ItemCount", 0),
                    "AttributeDefinitions": table_desc.get("AttributeDefinitions", []),
                    "KeySchema": table_desc.get("KeySchema", []),
                    "BillingModeSummary": table_desc.get("BillingModeSummary"),
                    "ProvisionedThroughput": table_desc.get("ProvisionedThroughput"),
                    "StreamSpecification": table_desc.get("StreamSpecification"),
                    "LatestStreamArn": table_desc.get("LatestStreamArn"),
                    "GlobalSecondaryIndexes": table_desc.get("GlobalSecondaryIndexes", []),
                    "LocalSecondaryIndexes": table_desc.get("LocalSecondaryIndexes", []),
                    "RestoreSummary": table_desc.get("RestoreSummary"),
                    "SSEDescription": table_desc.get("SSEDescription"),
                    "ArchivalSummary": table_desc.get("ArchivalSummary"),
                    "TableClass": table_desc.get("TableClass"),
                }
                
                # Get table tags
                try:
                    tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_desc.get("TableArn"))
                    table_info["Tags"] = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}
                except ClientError as e:
                    print(f"      ⚠ Error getting tags: {e}")
                    table_info["Tags"] = {}
                
                tables_data["tables"].append(table_info)
                
            except ClientError as e:
                print(f"      ⚠ Error getting table details: {e}")
        
        tables_data["total_tables"] = len(tables_data["tables"])
        
        # Save single combined file
        filename = "dynamodb_tables.json"
        filepath = _save_json_file(output_dir, filename, tables_data)
        if filepath:
            print(f"\n[✓] Saved tables → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

