"""
DynamoDB Streams Collector
Collects DynamoDB stream information.
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


def _get_dynamodbstreams_client(region):
    """DynamoDB Streams client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("dynamodbstreams")


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


def run_dynamodb_streams(args):
    """Collect DynamoDB streams."""
    print(f"[+] DynamoDB Streams Collector")
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
        streams_client = _get_dynamodbstreams_client(args.region)
    except Exception as e:
        print(f"❌ Error getting DynamoDB client: {e}")
        return
    
    try:
        streams_data = {
            "streams": [],
        }
        
        print("[+] Finding tables with streams enabled...")
        paginator = dynamodb_client.get_paginator("list_tables")
        table_names = []
        for page in paginator.paginate():
            table_names.extend(page.get("TableNames", []))
        
        # Check each table for streams
        for table_name in table_names:
            try:
                table_response = dynamodb_client.describe_table(TableName=table_name)
                table_desc = table_response.get("Table", {})
                stream_arn = table_desc.get("LatestStreamArn")
                
                if stream_arn:
                    print(f"[+] Collecting stream for table: {table_name}")
                    stream_info = {
                        "TableName": table_name,
                        "StreamArn": stream_arn,
                        "StreamSpecification": table_desc.get("StreamSpecification", {}),
                    }
                    
                    # Get stream details
                    try:
                        stream_response = streams_client.describe_stream(StreamArn=stream_arn)
                        stream_desc = stream_response.get("StreamDescription", {})
                        stream_info["StreamDetails"] = {
                            "StreamArn": stream_desc.get("StreamArn"),
                            "StreamLabel": stream_desc.get("StreamLabel"),
                            "StreamStatus": stream_desc.get("StreamStatus"),
                            "StreamViewType": stream_desc.get("StreamViewType"),
                            "CreationRequestDateTime": str(stream_desc.get("CreationRequestDateTime", "")),
                            "TableName": stream_desc.get("TableName", {}).get("TableName"),
                            "KeySchema": stream_desc.get("KeySchema", []),
                            "Shards": stream_desc.get("Shards", []),
                        }
                    except ClientError as e:
                        print(f"      ⚠ Error getting stream details: {e}")
                    
                    streams_data["streams"].append(stream_info)
            except ClientError as e:
                print(f"      ⚠ Error checking table {table_name}: {e}")
        
        streams_data["total_streams"] = len(streams_data["streams"])
        print(f"    ✓ Found {streams_data['total_streams']} stream(s)")
        
        # Save single combined file
        filename = "dynamodb_streams.json"
        filepath = _save_json_file(output_dir, filename, streams_data)
        if filepath:
            print(f"\n[✓] Saved streams → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

